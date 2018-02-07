//
//  WebService.m
//  Common
//
//  Created by 黄磊 on 16/4/6.
//  Copyright © 2016年 Musjoy. All rights reserved.
//

#import "MJWebService.h"
#import "AFHTTPSessionManager.h"
#import "AFNetworkReachabilityManager.h"
#import HEADER_ANALYSE
#import HEADER_LOCALIZE
#import HEADER_FILE_SOURCE

#define REQUEST_TIMEOUT 30
#define UPLOAD_TIMEOUT 120
#define DOWNLOAD_TIMEOUT 60


static AFNetworkReachabilityManager *s_hostReach = nil;

static MJReachabilityStatus g_reachableState = MJReachabilityStatusUnknown;

static MJURLSessionDidReceiveChallengeBlock s_sessionDidReceiveChallengeBlock = NULL;

NSString * MJStringFromReachabilityStatus(MJReachabilityStatus status) {
    switch (status) {
        case MJReachabilityStatusNotReachable:
            return locString(@"Not Reachable");
        case MJReachabilityStatusReachableViaWWAN:
            return locString(@"Reachable via WWAN");
        case MJReachabilityStatusReachableViaWiFi:
            return locString(@"Reachable via WiFi");
        case MJReachabilityStatusUnknown:
        default:
            return locString(@"Unknown");
    }
}


@interface MJWebService ()

@property (nonatomic, strong) MJURLSessionDidReceiveChallengeBlock sesionDidReceiveChallengeBlock;

@end


@implementation MJWebService

+ (void)dataInit
{
    if (s_hostReach == nil) {
        // 开启网络监听
        g_reachableState = MJReachabilityStatusUnknown;
        s_hostReach = [AFNetworkReachabilityManager sharedManager];
        [s_hostReach setReachabilityStatusChangeBlock:^(AFNetworkReachabilityStatus status) {
            LogTrace(@"Reachability changed to [%@]!", AFStringFromNetworkReachabilityStatus(status));
            g_reachableState = (MJReachabilityStatus)status;
            [[NSNotificationCenter defaultCenter] postNotificationName:kNoticReachabilityChange object:[NSNumber numberWithInteger:g_reachableState]];
            if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
                [[NSNotificationCenter defaultCenter] postNotificationName:kNoticLoseNetwork object:[NSNumber numberWithInteger:g_reachableState]];
            } else {
                [[NSNotificationCenter defaultCenter] postNotificationName:kNoticGetNetwork object:[NSNumber numberWithInteger:g_reachableState]];
            }
        }];
        [s_hostReach startMonitoring];  //开始监听，会启动一个run loop
        g_reachableState = (MJReachabilityStatus)s_hostReach.networkReachabilityStatus;
        
        if (s_sessionDidReceiveChallengeBlock == NULL) {
            
            NSArray *arrTrustList = getFileData(FILE_NAME_CER_TRUST_LIST);
            if (arrTrustList == nil) {
                arrTrustList = SERVER_CER_TRUST_LIST;
            }
            NSMutableDictionary *dicTrusts = [[NSMutableDictionary alloc] init];
            for (NSString *ca in arrTrustList) {
                [dicTrusts setObject:@YES forKey:ca];
            }
            
            s_sessionDidReceiveChallengeBlock = ^NSURLSessionAuthChallengeDisposition(NSString *domain, NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
                *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
                SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
                CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
                if (certificateCount > 0) {
                    SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, certificateCount-1);
                    CFStringRef strSummaryRef = SecCertificateCopySubjectSummary(certificate);
                    NSString *strSummary = (NSString *)CFBridgingRelease(strSummaryRef);
                    if (domain.length > 0) {
                        triggerEventStr(STAT_DOMAIN_ROOT_CA, ([NSString stringWithFormat:@"%@-%@", domain, strSummary]));
                    }
                    if (strSummary && [dicTrusts objectForKey:strSummary]) {
                        return NSURLSessionAuthChallengePerformDefaultHandling;
                    } else {
                        LogError(@"\n\t%@ is not a trusted root CA", strSummary);
                        return NSURLSessionAuthChallengeCancelAuthenticationChallenge;
                    }
                }
                return NSURLSessionAuthChallengePerformDefaultHandling;
            };
        }
    }
}

+ (MJReachabilityStatus)reachableState
{
    return g_reachableState;
}

+ (void)setSesionDidReceiveChallengeBlock:(MJURLSessionDidReceiveChallengeBlock)sesionDidReceiveChallengeBlock
{
    s_sessionDidReceiveChallengeBlock = sesionDidReceiveChallengeBlock;
}

#ifdef FUN_NEED_SECURITY_REQUEST
// 坚持请求是否安全，返回也是表示安装可以继续操作，返回NO，表示未检查完成或不安全
+ (BOOL)checkRequestSecurity:(NSString *)serverUrl completion:(void(^)(BOOL isSucceed, NSError *err))completion
{
    if (serverUrl.length == 0) {
        return NO;
    }
    if (![serverUrl hasPrefix:@"https"]) {
        return YES;
    }
    static NSMutableDictionary *s_dicHostCheckResult = nil;
    if (s_dicHostCheckResult == nil) {
        s_dicHostCheckResult = [[NSMutableDictionary alloc] init];
    }
    NSURL *url = [NSURL URLWithString:serverUrl];
    NSString *hostUrl = [NSString stringWithFormat:@"%@://%@", url.scheme, url.host];
    
    NSMutableDictionary *curCheckResult = [s_dicHostCheckResult objectForKey:hostUrl];
    if (curCheckResult) {
        BOOL securityHaveChecked = [[curCheckResult objectForKey:@"securityHaveChecked"] boolValue];
        BOOL isRequestSecurity = [[curCheckResult objectForKey:@"isRequestSecurity"] boolValue];
        if (securityHaveChecked) {
            if (!isRequestSecurity) {
                // 这里不回掉的话将没有地方回掉
                NSError *errCheck = [curCheckResult objectForKey:@"errCheck"];
                completion(isRequestSecurity, errCheck);
            }
            return isRequestSecurity;
        }
    } else {
        curCheckResult = [[NSMutableDictionary alloc] init];
        NSMutableArray *arrCheckCompletion = [[NSMutableArray alloc] init];
        [curCheckResult setObject:arrCheckCompletion forKey:@"arrCheckCompletion"];
        [s_dicHostCheckResult setObject:curCheckResult forKey:hostUrl];
    }
    
    NSMutableArray *arrCheckCompletion = [curCheckResult objectForKey:@"arrCheckCompletion"];
    
    BOOL isInChek = [[curCheckResult objectForKey:@"isInChek"] boolValue];
    if (isInChek) {
        [arrCheckCompletion addObject:completion];
        return NO;
    }
    [curCheckResult setObject:@YES forKey:@"isInChek"];
    
    [curCheckResult setObject:@NO forKey:@"haveCheck"];
    
    void(^requestRespond)(BOOL, NSError *) = ^(BOOL needRecheck, NSError *err) {
        BOOL haveCheck = [[curCheckResult objectForKey:@"haveCheck"] boolValue];
        BOOL securityHaveChecked = YES;
        BOOL isRequestSecurity = needRecheck?NO:haveCheck;
        [curCheckResult setObject:[NSNumber numberWithBool:YES] forKey:@"securityHaveChecked"];
        [curCheckResult setObject:[NSNumber numberWithBool:isRequestSecurity] forKey:@"isRequestSecurity"];
        if (!isRequestSecurity && err == nil) {
            err = [self errorForbidden];
        }
        if (err) {
            [curCheckResult setObject:err forKey:@"errCheck"];
        } else {
            [curCheckResult removeObjectForKey:@"errCheck"];
        }
        [curCheckResult setObject:@NO forKey:@"isInChek"];
        NSArray *arrCompletion = [arrCheckCompletion copy];
        if ([arrCompletion count] > 0) {
            for (void(^aCompletion)(BOOL, NSError *) in arrCompletion) {
                aCompletion(isRequestSecurity, err);
            }
            [arrCheckCompletion removeAllObjects];
        }
        completion(isRequestSecurity, err);
        securityHaveChecked = !needRecheck;
        [curCheckResult setObject:[NSNumber numberWithBool:securityHaveChecked] forKey:@"securityHaveChecked"];
    };
    
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    manager.requestSerializer.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    
    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        [curCheckResult setObject:@YES forKey:@"haveCheck"];
        return s_sessionDidReceiveChallengeBlock(url.host, session, challenge, credential);
    }];
    
    [manager GET:hostUrl parameters:nil progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        requestRespond(NO, nil);
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        if (task
            && [task.response isKindOfClass:[NSHTTPURLResponse class]]
            && [(NSHTTPURLResponse *)task.response statusCode] >= 200) {
            requestRespond(NO, nil);
        } else {
            requestRespond(YES, error);
        }
    }];
    return NO;
}
#endif

#pragma mark - 发起GET请求

+ (void)startGet:(NSString *)serverUrl
            body:(NSDictionary *)body
      completion:(MJResponseBlock)completion
{
    [self startGet:serverUrl header:nil body:body completion:completion];
}

+ (void)startGetText:(NSString *)serverUrl
                body:(NSDictionary *)body
          completion:(MJResponseBlock)completion
{
    [self startGet:serverUrl header:@{@"textResponse":@YES} body:body completion:completion];
}

+ (void)startGet:(NSString *)serverUrl
          header:(NSDictionary *)header
            body:(NSDictionary *)body
      completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return;
    }
#ifdef FUN_NEED_SECURITY_REQUEST
    BOOL checkResult = [self checkRequestSecurity:serverUrl completion:^(BOOL isSucceed, NSError *err) {
        if (isSucceed) {
            [self startGet:serverUrl header:header body:body completion:completion];
        } else {
            completion ? completion(nil, nil, err) : 0;
        }
    }];
    if (!checkResult) {
        return;
    }
#endif
    
    // 拼接请求url
    NSString *pathUrl = [serverUrl stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager = [self managerWithHeader:header];
    
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    
    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengeBlock(nil, session, challenge, credential);
    }];
    
    [manager GET:pathUrl parameters:body progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
    }];
}

#pragma mark - 发起POST请求

+ (void)startPost:(NSString *)serverUrl
             body:(NSDictionary *)body
       completion:(MJResponseBlock)completion
{
    [self startPost:serverUrl header:nil body:body completion:completion];
}

+ (void)startPost:(NSString *)serverUrl
           header:(NSDictionary *)header
             body:(NSDictionary *)body
       completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return;
    }
#ifdef FUN_NEED_SECURITY_REQUEST
    BOOL checkResult = [self checkRequestSecurity:serverUrl completion:^(BOOL isSucceed, NSError *err) {
        if (isSucceed) {
            [self startPost:serverUrl header:header body:body completion:completion];
        } else {
            completion ? completion(nil, nil, err) : 0;
        }
    }];
    if (!checkResult) {
        return;
    }
#endif
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager = [self managerWithHeader:header];
    
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];

    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengeBlock(nil, session, challenge, credential);
    }];
    
    [manager POST:pathUrl parameters:body progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
    }];
}

#pragma mark - 发起Put请求

+ (void)startPut:(NSString *)serverUrl
            body:(NSDictionary *)body
      completion:(MJResponseBlock)completion
{
    [self startPut:serverUrl header:nil body:body completion:completion];
}

+ (void)startPut:(NSString *)serverUrl
          header:(NSDictionary *)header
            body:(NSDictionary *)body
      completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return;
    }
#ifdef FUN_NEED_SECURITY_REQUEST
    BOOL checkResult = [self checkRequestSecurity:serverUrl completion:^(BOOL isSucceed, NSError *err) {
        if (isSucceed) {
            [self startPut:serverUrl header:header body:body completion:completion];
        } else {
            completion ? completion(nil, nil, err) : 0;
        }
    }];
    if (!checkResult) {
        return;
    }
#endif
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager = [self managerWithHeader:header];
    
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    
    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengeBlock(nil, session, challenge, credential);
    }];
    
    [manager PUT:pathUrl parameters:body success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
    }];
}

#pragma mark - 发起Delete请求

+ (void)startDelete:(NSString *)serverUrl
               body:(NSDictionary *)body
         completion:(MJResponseBlock)completion
{
    [self startDelete:serverUrl header:nil body:body completion:completion];
}

+ (void)startDelete:(NSString *)serverUrl
             header:(NSDictionary *)header
               body:(NSDictionary *)body
         completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return ;
    }
#ifdef FUN_NEED_SECURITY_REQUEST
    BOOL checkResult = [self checkRequestSecurity:serverUrl completion:^(BOOL isSucceed, NSError *err) {
        if (isSucceed) {
            [self startDelete:serverUrl header:header body:body completion:completion];
        } else {
            completion ? completion(nil, nil, err) : 0;
        }
    }];
    if (!checkResult) {
        return;
    }
#endif
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager = [self managerWithHeader:header];
    
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];

    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengeBlock(nil, session, challenge, credential);
    }];
    
    [manager DELETE:pathUrl parameters:body success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
    }];
}


#pragma mark - 发起Upload请求

/** 多文件上传 */
+ (void)startUploadFiles:(NSString *)serverUrl
                    body:(NSDictionary *)body
                   files:(NSArray *)files
              completion:(MJResponseBlock)completion
{
    [self startUploadFiles:serverUrl header:nil body:body files:files completion:completion];
}

+ (void)startUploadFiles:(NSString *)serverUrl
                  header:(NSDictionary *)header
                    body:(NSDictionary *)body
                   files:(NSArray *)files
              completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return;
    }
#ifdef FUN_NEED_SECURITY_REQUEST
    BOOL checkResult = [self checkRequestSecurity:serverUrl completion:^(BOOL isSucceed, NSError *err) {
        if (isSucceed) {
            [self startUploadFiles:serverUrl header:header body:body files:files completion:completion];
        } else {
            completion ? completion(nil, nil, err) : 0;
        }
    }];
    if (!checkResult) {
        return;
    }
#endif
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestData: %@\n", body);
    
    AFHTTPSessionManager *manager = [self managerWithHeader:header];
    
    [manager.requestSerializer setTimeoutInterval:UPLOAD_TIMEOUT];

    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengeBlock(nil, session, challenge, credential);
    }];
    
    [manager POST:pathUrl parameters:body constructingBodyWithBlock:^(id<AFMultipartFormData>  _Nonnull formData) {
        for (NSString *filePath in files) {
            LogInfo(@"本地文件全路径:%@", filePath);
            NSData *audioData = [NSData dataWithContentsOfFile:filePath];
            // 文件类型判断，需要优化
            NSString *mineType = @"audio/speex";
            if ([filePath hasSuffix:@"png"] || [filePath hasSuffix:@"jpg"]) {
                mineType = @"image/jpg";
            } else if ([filePath hasSuffix:@"gif"]) {
                mineType = @"image/gif";
            }
            if (audioData) {
                [formData appendPartWithFileData:audioData name:@"fileData[]" fileName:[filePath lastPathComponent] mimeType:mineType];
            }
        }
    } progress:^(NSProgress * _Nonnull uploadProgress) {
        
        
    } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
    }];
}


#pragma mark - 发起Download请求

/** 单个文件下载 */
+ (void)startDownload:(NSString *)remotePath
         withSavePath:(NSString *)localPath
           completion:(MJResponseBlock)completion
        progressBlock:(void (^)(NSUInteger bytesRead, long long totalBytesRead, long long totalBytesExpectedToRead))progressBlock
{
    [self startDownload:remotePath header:nil body:nil withSavePath:localPath completion:completion progressBlock:progressBlock];
}

+ (void)startDownload:(NSString *)remotePath
               header:(NSDictionary *)header
                 body:(NSDictionary *)body
         withSavePath:(NSString *)localPath
           completion:(MJResponseBlock)completion
        progressBlock:(void (^)(NSUInteger bytesRead, long long totalBytesRead, long long totalBytesExpectedToRead))progressBlock
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return;
    }
#ifdef FUN_NEED_SECURITY_REQUEST
    BOOL checkResult = [self checkRequestSecurity:remotePath completion:^(BOOL isSucceed, NSError *err) {
        if (isSucceed) {
            [self startDownload:remotePath header:header body:body withSavePath:localPath completion:completion progressBlock:progressBlock];
        } else {
            completion ? completion(nil, nil, err) : 0;
        }
    }];
    if (!checkResult) {
        return;
    }
#endif
    
    LogTrace(@"...>>>...Start download file : %@\n", remotePath);
    
    NSString *remoteFilePath = remotePath;
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:remoteFilePath]
                                                           cachePolicy:NSURLRequestReloadIgnoringCacheData
                                                       timeoutInterval:DOWNLOAD_TIMEOUT];
    
    if (header && header.allKeys.count > 0) {
        for (NSString *aKey in header.allKeys) {
            NSString *aValue = header[aKey];
            [request setValue:aValue forHTTPHeaderField:aKey];
        }
    }
    
    // 避免同时下载数据到同一个文件
    NSString *filePathTemp = [NSString stringWithFormat:@"%@.temp",localPath];   //临时下载的文件路径
    int count = 1;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    while ([fileManager fileExistsAtPath:filePathTemp]) {
        filePathTemp = [NSString stringWithFormat:@"%@.temp_%d", localPath, count];
        count ++;
    }
    
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    AFURLSessionManager *manager = [[AFURLSessionManager alloc] initWithSessionConfiguration:configuration];
    
    AFHTTPRequestSerializer *requestSerializer = [AFHTTPRequestSerializer serializer];
    request = [[requestSerializer requestBySerializingRequest:request withParameters:body error:NULL] mutableCopy];

    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengeBlock(nil, session, challenge, credential);
    }];
    
    NSURLSessionDownloadTask *downloadTask = [manager downloadTaskWithRequest:request progress:^(NSProgress * _Nonnull downloadProgress) {
        // 下载进度
        float progress = (float)downloadProgress.completedUnitCount / downloadProgress.totalUnitCount;
        // 下载完成...该方法会在下载完成后立即执行
        if (progress >= 1.0) {
            LogInfo(@"下载完成...");
        }
        if (progressBlock) {
            progressBlock(0, downloadProgress.completedUnitCount, downloadProgress.totalUnitCount);
        }
    } destination:^NSURL * _Nonnull(NSURL * _Nonnull targetPath, NSURLResponse * _Nonnull response) {
        return [NSURL fileURLWithPath:filePathTemp];
    } completionHandler:^(NSURLResponse * _Nonnull response, NSURL * _Nullable filePath, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                // 下载失败
                LogError(@"...>>>...Network error: %@ %@\n", remotePath, error.localizedDescription);
            }
            NSFileManager *fileManager = [NSFileManager defaultManager];
            NSError *err = nil;
            if ([fileManager fileExistsAtPath:filePathTemp]) {
                if (error) {
                    [fileManager removeItemAtPath:filePathTemp error:NULL];
                } else {
                    LogInfo(@"...>>>...Successfully downloaded file\n\t %@\n\tto %@\n", remotePath, localPath);
                    if ([fileManager fileExistsAtPath:localPath]) {
                        [fileManager removeItemAtPath:localPath error:&err];
                    }
                    if (!err) {
                        [fileManager moveItemAtPath:filePathTemp toPath:localPath error:&err];
                    }
                }
            }
            completion ? completion(response, filePath, err?:error) : nil;
        });
    }];
    [downloadTask resume];
}

#pragma mark - Private

+ (NSError *)errorOffNet
{
    static NSError *err;
    if (err == nil) {
        err = [[NSError alloc] initWithDomain:kErrorDomainWebService
                                         code:sNetworkCodeOffNet
                                     userInfo:@{
                                                NSLocalizedDescriptionKey:locString(sNetworkUnreachMsg),
                                                NSLocalizedFailureReasonErrorKey:locString(sNetworkUnreachMsg)
                                                }];
    }
    return err;
}

+ (NSError *)errorForbidden
{
    static NSError *err;
    if (err == nil) {
        err = [[NSError alloc] initWithDomain:kErrorDomainWebService
                                         code:sNetworkCodeForbidden
                                     userInfo:@{
                                                NSLocalizedDescriptionKey:locString(sNetworkForbidden),
                                                NSLocalizedFailureReasonErrorKey:locString(sNetworkForbidden)
                                                }];
    }
    return err;
}

+ (AFHTTPSessionManager *)managerWithHeader:(NSDictionary *)header
{
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    
    if (header && header.allKeys.count > 0) {
        NSMutableDictionary *dicHeader = [header mutableCopy];
        if (dicHeader[@"jsonRequest"] && [dicHeader[@"jsonRequest"] boolValue]) {
            manager.requestSerializer = [AFJSONRequestSerializer serializer];
            [dicHeader removeObjectForKey:@"jsonRequest"];
        }
        if (dicHeader[@"textResponse"] && [dicHeader[@"textResponse"] boolValue]) {
            manager.responseSerializer = [AFHTTPResponseSerializer serializer];
            [dicHeader removeObjectForKey:@"textResponse"];
        }
        for (NSString *aKey in dicHeader.allKeys) {
            NSString *aValue = dicHeader[aKey];
            [manager.requestSerializer setValue:aValue
                             forHTTPHeaderField:aKey];
        }
    }
    return manager;
}

@end
