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
#import HEADER_LOCALIZE
#import HEADER_FILE_SOURCE

#define REQUEST_TIMEOUT 30
#define UPLOAD_TIMEOUT 120
#define DOWNLOAD_TIMEOUT 60


static AFNetworkReachabilityManager *s_hostReach = nil;

static MJReachabilityStatus g_reachableState = MJReachabilityStatusUnknown;

static MJURLSessionDidReceiveChallengeBlock s_sessionDidReceiveChallengBlock = NULL;

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
        
        if (s_sessionDidReceiveChallengBlock == NULL) {
            
            NSArray *arrTrustList = getFileData(FILE_NAME_CER_TRUST_LIST);
            if (arrTrustList == nil) {
                arrTrustList = SERVER_CER_TRUST_LIST;
            }
            NSMutableDictionary *dicTrusts = [[NSMutableDictionary alloc] init];
            for (NSString *ca in arrTrustList) {
                [dicTrusts setObject:@YES forKey:ca];
            }
            
            s_sessionDidReceiveChallengBlock = ^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
                *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
                SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
                CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
                if (certificateCount > 0) {
                    SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, certificateCount-1);
                    CFStringRef strSummaryRef = SecCertificateCopySubjectSummary(certificate);
                    NSString *strSummary = (__bridge NSString *)strSummaryRef;
                    CFRelease(strSummaryRef);
                    if (strSummary && [dicTrusts objectForKey:strSummary]) {
                        return NSURLSessionAuthChallengeUseCredential;
                    } else {
                        LogError(@"\n\t%@ is not a trusted root CA", strSummary);
                    }
                }
                return NSURLSessionAuthChallengeUseCredential;
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
    s_sessionDidReceiveChallengBlock = sesionDidReceiveChallengeBlock;
}

#pragma mark - 发起GET请求

+ (BOOL)startGet:(NSString *)serverUrl
            body:(NSDictionary *)body
      completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomainWebService
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:locString(sNetworkErrorMsg),
                                                         NSLocalizedFailureReasonErrorKey:locString(sNetworkErrorMsg)
                                                         }];
        completion ? completion(nil, nil, err) : 0;
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = [serverUrl stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    
    if ([body[@"Authorization"] length] > 0) {
        [manager.requestSerializer setValue:body[@"Authorization"]
                         forHTTPHeaderField:@"Authorization"];

    }
    
    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengBlock(session, challenge, credential);
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
    return YES;
}

+ (BOOL)startGetText:(NSString *)serverUrl
                body:(NSDictionary *)body
          completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomainWebService
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:locString(sNetworkErrorMsg),
                                                         NSLocalizedFailureReasonErrorKey:locString(sNetworkErrorMsg)
                                                         }];
        completion ? completion(nil, nil, err) : 0;
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = [serverUrl stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    
    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengBlock(session, challenge, credential);
    }];
    
    [manager GET:pathUrl parameters:body progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        if (responseObject && [responseObject isKindOfClass:[NSData class]]) {
            responseObject = [[NSString alloc] initWithData:responseObject encoding:NSUTF8StringEncoding];
        }
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
    }];
    return YES;
}

#pragma mark - 发起POST请求

+ (BOOL)startPost:(NSString *)serverUrl
             body:(NSDictionary *)body
       completion:(MJResponseBlock)completion
{
    return [self startPost:serverUrl header:nil body:body completion:completion];
}

+ (BOOL)startPost:(NSString *)serverUrl
           header:(NSDictionary *)header
             body:(NSDictionary *)body
       completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomainWebService
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:locString(sNetworkErrorMsg),
                                                         NSLocalizedFailureReasonErrorKey:locString(sNetworkErrorMsg)
                                                         }];
        completion ? completion(nil, nil, err) : 0;
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    if (body[@"isJsonRequest"] && [body[@"isJsonRequest"] boolValue]) {
        manager.requestSerializer = [AFJSONRequestSerializer serializer];
    } else {
        manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    }
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];

    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengBlock(session, challenge, credential);
    }];
    
    if ([body[@"Authorization"] length] > 0) {
        [manager.requestSerializer setValue:body[@"Authorization"]
                         forHTTPHeaderField:@"Authorization"];
        
    }
    if (header && header.allKeys.count > 0) {
        for (NSString *aKey in header.allKeys) {
            NSString *aValue = header[aKey];
            [manager.requestSerializer setValue:aValue
                             forHTTPHeaderField:aKey];
        }
    }
    
    [manager POST:pathUrl parameters:body progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
    }];
    return YES;
}

#pragma mark - 发起Put请求

+ (BOOL)startPut:(NSString *)serverUrl
            body:(NSDictionary *)body
      completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomainWebService
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:locString(sNetworkErrorMsg),
                                                         NSLocalizedFailureReasonErrorKey:locString(sNetworkErrorMsg)
                                                         }];
        completion ? completion(nil, nil, err) : 0;
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    if (body[@"isJsonRequest"] && [body[@"isJsonRequest"] boolValue]) {
        manager.requestSerializer = [AFJSONRequestSerializer serializer];
    } else {
        manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    }
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];

    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengBlock(session, challenge, credential);
    }];
    
    if ([body[@"Authorization"] length] > 0) {
        [manager.requestSerializer setValue:body[@"Authorization"]
                         forHTTPHeaderField:@"Authorization"];
        
    }
    
    [manager PUT:pathUrl parameters:body success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
    }];
    return YES;
}

#pragma mark - 发起Delete请求

+ (BOOL)startDelete:(NSString *)serverUrl
               body:(NSDictionary *)body
         completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomainWebService
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:locString(sNetworkErrorMsg),
                                                         NSLocalizedFailureReasonErrorKey:locString(sNetworkErrorMsg)
                                                         }];
        completion ? completion(nil, nil, err) : 0;
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    if (body[@"isJsonRequest"] && [body[@"isJsonRequest"] boolValue]) {
        manager.requestSerializer = [AFJSONRequestSerializer serializer];
    } else {
        manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    }
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];

    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengBlock(session, challenge, credential);
    }];
    
    if ([body[@"Authorization"] length] > 0) {
        [manager.requestSerializer setValue:body[@"Authorization"]
                         forHTTPHeaderField:@"Authorization"];
        
    }
    
    [manager DELETE:pathUrl parameters:body success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
    }];
    return YES;
}


#pragma mark - 发起Upload请求

/** 多文件上传 */
+ (BOOL)startUploadFiles:(NSString *)serverUrl
                    body:(NSDictionary *)body
                   files:(NSArray *)files
              completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomainWebService
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:locString(sNetworkErrorMsg),
                                                         NSLocalizedFailureReasonErrorKey:locString(sNetworkErrorMsg)
                                                         }];
        completion ? completion(nil, nil, err) : 0;
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestData: %@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:UPLOAD_TIMEOUT];

    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengBlock(session, challenge, credential);
    }];
    
    if ([body[@"Authorization"] length] > 0) {
        [manager.requestSerializer setValue:body[@"Authorization"]
                         forHTTPHeaderField:@"Authorization"];
        
    }
    
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
    return YES;
}


#pragma mark - 发起Download请求

/** 单个文件下载 */
+ (void)startDownload:(NSString *)remotePath
         withSavePath:(NSString *)localPath
           completion:(MJResponseBlock)completion
        progressBlock:(void (^)(NSUInteger bytesRead, long long totalBytesRead, long long totalBytesExpectedToRead))progressBlock
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomainWebService
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:locString(sNetworkErrorMsg),
                                                         NSLocalizedFailureReasonErrorKey:locString(sNetworkErrorMsg)
                                                         }];
        completion ? completion(nil, nil, err) : 0;
        return;
    }
    
    LogTrace(@"...>>>...Start download file : %@\n", remotePath);
    
    NSString *remoteFilePath = remotePath;
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:remoteFilePath]
                                             cachePolicy:NSURLRequestReloadIgnoringCacheData
                                         timeoutInterval:DOWNLOAD_TIMEOUT];
    
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

    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengBlock(session, challenge, credential);
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



@end
