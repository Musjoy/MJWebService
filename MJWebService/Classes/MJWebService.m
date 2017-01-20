//
//  WebService.m
//  Common
//
//  Created by 黄磊 on 16/4/6.
//  Copyright © 2016年 Musjoy. All rights reserved.
//

#import "MJWebService.h"


#define REQUEST_TIMEOUT 30
#define UPLOAD_TIMEOUT 120
#define DOWNLOAD_TIMEOUT 60



static AFNetworkReachabilityManager *s_hostReach = nil;

static AFNetworkReachabilityStatus g_reachableState = AFNetworkReachabilityStatusUnknown;


@interface MJWebService ()


@end


@implementation MJWebService

+ (void)dataInit
{
    if (s_hostReach == nil) {
        // 开启网络监听
        g_reachableState = AFNetworkReachabilityStatusUnknown;
        s_hostReach = [AFNetworkReachabilityManager sharedManager];
        [s_hostReach setReachabilityStatusChangeBlock:^(AFNetworkReachabilityStatus status) {
            LogTrace(@"Reachability changed to [%@]!", AFStringFromNetworkReachabilityStatus(status));
            g_reachableState = status;
            [[NSNotificationCenter defaultCenter] postNotificationName:kNoticReachabilityChange object:[NSNumber numberWithInteger:g_reachableState]];
            if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
                [[NSNotificationCenter defaultCenter] postNotificationName:kNoticLoseNetwork object:[NSNumber numberWithInteger:g_reachableState]];
            } else {
                [[NSNotificationCenter defaultCenter] postNotificationName:kNoticGetNetwork object:[NSNumber numberWithInteger:g_reachableState]];
            }
        }];
        [s_hostReach startMonitoring];  //开始监听，会启动一个run loop
        g_reachableState = s_hostReach.networkReachabilityStatus;
    }
}

+ (AFNetworkReachabilityStatus)reachableState
{
    return g_reachableState;
}


#pragma mark - 发起GET请求

+ (BOOL)startGet:(NSString *)serverUrl
            body:(NSDictionary *)body
         success:(RequestSuccessBlock)sblock
         failure:(RequestFailureBlock)fblock
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomain
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:sNetworkErrorMsg,
                                                         NSLocalizedFailureReasonErrorKey:sNetworkErrorMsg
                                                         }];
        if (fblock) {
            fblock(err);
        }
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = [serverUrl stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    LogTrace(@"...>>>...requestUrl:%@\n", pathUrl);
    LogDebug(@"...>>>...requestBody:%@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    
    if ([body[@"Authorization"] length] > 0) {
        [manager.requestSerializer setValue:body[@"Authorization"]
                         forHTTPHeaderField:@"Authorization"];

    }
    
    // 信任无效证实
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        return NSURLSessionAuthChallengeUseCredential;
    }];
    
    [manager GET:pathUrl parameters:body progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        if (sblock) {
            sblock(responseObject);
        }
        
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@\n", error);
        if (fblock) {
            fblock(error);
        }
    }];
    return YES;
}

+ (BOOL)startGetText:(NSString *)serverUrl
                body:(NSDictionary *)body
             success:(RequestSuccessBlock)sblock
             failure:(RequestFailureBlock)fblock
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomain
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:sNetworkErrorMsg,
                                                         NSLocalizedFailureReasonErrorKey:sNetworkErrorMsg
                                                         }];
        if (fblock) {
            fblock(err);
        }
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = [serverUrl stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    LogTrace(@"...>>>...requestUrl:%@\n", pathUrl);
    LogDebug(@"...>>>...requestBody:%@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    
    // 信任无效证实
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        return NSURLSessionAuthChallengeUseCredential;
    }];
    
    [manager GET:pathUrl parameters:body progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        if (responseObject && [responseObject isKindOfClass:[NSData class]]) {
            responseObject = [[NSString alloc] initWithData:responseObject encoding:NSUTF8StringEncoding];
        }
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        if (sblock) {
            sblock(responseObject);
        }
        
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@\n", error);
        if (fblock) {
            fblock(error);
        }
    }];
    return YES;
}

#pragma mark - 发起POST请求

+ (BOOL)startPost:(NSString *)serverUrl
             body:(NSDictionary *)body
          success:(RequestSuccessBlock)sblock
          failure:(RequestFailureBlock)fblock
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomain
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:sNetworkErrorMsg,
                                                         NSLocalizedFailureReasonErrorKey:sNetworkErrorMsg
                                                         }];
        if (fblock) {
            fblock(err);
        }
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl:%@\n", pathUrl);
    LogDebug(@"...>>>...requestBody:%@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    if (body[@"isJsonRequest"] && [body[@"isJsonRequest"] boolValue]) {
        manager.requestSerializer = [AFJSONRequestSerializer serializer];
    } else {
        manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    }
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        return NSURLSessionAuthChallengeUseCredential;
    }];
    
    if ([body[@"Authorization"] length] > 0) {
        [manager.requestSerializer setValue:body[@"Authorization"]
                         forHTTPHeaderField:@"Authorization"];
        
    }
    
    [manager POST:pathUrl parameters:body progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        if (sblock) {
            sblock(responseObject);
        }
        
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@\n", error);
        if (fblock) {
            fblock(error);
        }
    }];
    return YES;
}

#pragma mark - 发起Put请求

+ (BOOL)startPut:(NSString *)serverUrl
            body:(NSDictionary *)body
         success:(RequestSuccessBlock)sblock
         failure:(RequestFailureBlock)fblock
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomain
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:sNetworkErrorMsg,
                                                         NSLocalizedFailureReasonErrorKey:sNetworkErrorMsg
                                                         }];
        if (fblock) {
            fblock(err);
        }
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl:%@\n", pathUrl);
    LogDebug(@"...>>>...requestBody:%@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    if (body[@"isJsonRequest"] && [body[@"isJsonRequest"] boolValue]) {
        manager.requestSerializer = [AFJSONRequestSerializer serializer];
    } else {
        manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    }
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        return NSURLSessionAuthChallengeUseCredential;
    }];
    
    if ([body[@"Authorization"] length] > 0) {
        [manager.requestSerializer setValue:body[@"Authorization"]
                         forHTTPHeaderField:@"Authorization"];
        
    }
    
    [manager PUT:pathUrl parameters:body success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        if (sblock) {
            sblock(responseObject);
        }
        
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@\n", error);
        if (fblock) {
            fblock(error);
        }
    }];
    return YES;
}

#pragma mark - 发起Delete请求

+ (BOOL)startDelete:(NSString *)serverUrl
               body:(NSDictionary *)body
            success:(RequestSuccessBlock)sblock
            failure:(RequestFailureBlock)fblock
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomain
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:sNetworkErrorMsg,
                                                         NSLocalizedFailureReasonErrorKey:sNetworkErrorMsg
                                                         }];
        if (fblock) {
            fblock(err);
        }
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl:%@\n", pathUrl);
    LogDebug(@"...>>>...requestBody:%@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    if (body[@"isJsonRequest"] && [body[@"isJsonRequest"] boolValue]) {
        manager.requestSerializer = [AFJSONRequestSerializer serializer];
    } else {
        manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    }
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        return NSURLSessionAuthChallengeUseCredential;
    }];
    
    if ([body[@"Authorization"] length] > 0) {
        [manager.requestSerializer setValue:body[@"Authorization"]
                         forHTTPHeaderField:@"Authorization"];
        
    }
    
    [manager DELETE:pathUrl parameters:body success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        if (sblock) {
            sblock(responseObject);
        }
        
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@\n", error);
        if (fblock) {
            fblock(error);
        }
    }];
    return YES;
}


#pragma mark - 发起Upload请求

/** 多文件上传 */
+ (BOOL)startUploadFiles:(NSString *)serverUrl
                    body:(NSDictionary *)body
                   files:(NSArray *)files
                 success:(RequestSuccessBlock)sblock
                 failure:(RequestFailureBlock)fblock
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomain
                                                  code:sNetworkOffNet
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:sNetworkErrorMsg,
                                                         NSLocalizedFailureReasonErrorKey:sNetworkErrorMsg
                                                         }];
        if (fblock) {
            fblock(err);
        }
        return NO;
    }
    
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl:%@\n", pathUrl);
    LogDebug(@"...>>>...requestData:%@\n", body);
    
    AFHTTPSessionManager *manager=[AFHTTPSessionManager manager];
    
    manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    manager.responseSerializer = [AFJSONResponseSerializer serializer];
    [manager.requestSerializer setTimeoutInterval:UPLOAD_TIMEOUT];
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        return NSURLSessionAuthChallengeUseCredential;
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
        if (sblock) {
            sblock(responseObject);
        }
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@\n", error);
        if (fblock) {
            fblock(error);
        }
    }];
    return YES;
}


#pragma mark - 发起Download请求

/** 单个文件下载 */
+ (void)startDownload:(NSString *)remotePath
         withSavePath:(NSString *)localPath
           completion:(void (^)(BOOL isSucceed, NSString *message))completion
        progressBlock:(void (^)(NSUInteger bytesRead, long long totalBytesRead, long long totalBytesExpectedToRead))progressBlock
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        if (completion) {
            completion(NO, sNetworkErrorMsg);
        }
        return;
    }
    
    if (completion == nil) {
        completion = ^(BOOL isSucceed, NSString *message) {};
    }
    
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
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        return NSURLSessionAuthChallengeUseCredential;
    }];
    
    NSURLSessionDownloadTask *downloadTask = [manager downloadTaskWithRequest:request progress:^(NSProgress * _Nonnull downloadProgress) {
        //下载进度
        float progress = (float)downloadProgress.completedUnitCount / downloadProgress.totalUnitCount;
        //下载完成...该方法会在下载完成后立即执行
        if (progress >= 1.0) {
            LogInfo(@"下载完成...");
        }
        if (progressBlock) {
            progressBlock(0, downloadProgress.completedUnitCount, downloadProgress.totalUnitCount);
        }
    } destination:^NSURL * _Nonnull(NSURL * _Nonnull targetPath, NSURLResponse * _Nonnull response) {
        return [NSURL fileURLWithPath:filePathTemp];
    } completionHandler:^(NSURLResponse * _Nonnull response, NSURL * _Nullable filePath, NSError * _Nullable error) {
        if (error) {
            // 下载失败
            LogError(@"...>>>...Network error: %@\n", error);
            dispatch_async(dispatch_get_main_queue(), ^{
                NSFileManager *fileManager = [NSFileManager defaultManager];
                NSError *err = nil;
                if ([fileManager fileExistsAtPath:filePathTemp]) {
                    [fileManager removeItemAtPath:filePathTemp error:&err];
                }
                completion(NO, @"Download failed!");
            });
        } else {
            LogInfo(@"...>>>...Successfully downloaded file to %@\n", localPath);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) {
                    NSFileManager *fileManager = [NSFileManager defaultManager];
                    NSError *err = nil;
                    if ([fileManager fileExistsAtPath:filePathTemp]) {
                        if ([fileManager fileExistsAtPath:localPath]) {
                            [fileManager removeItemAtPath:localPath error:&err];
                        }
                        [fileManager moveItemAtPath:filePathTemp toPath:localPath error:&err];
                    }
                    
                    completion(YES, @"Download succeed!");
                }
            });
        }
    }];
    [downloadTask resume];
}



@end
