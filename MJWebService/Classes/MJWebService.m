//
//  WebService.m
//  Common
//
//  Created by 黄磊 on 16/4/6.
//  Copyright © 2016年 Musjoy. All rights reserved.
//

#import "MJWebService.h"
#import <AFNetworking/AFHTTPSessionManager.h>
#import <AFNetworking/AFNetworkReachabilityManager.h>
#import HEADER_ANALYSE
#import HEADER_LOCALIZE
#import HEADER_FILE_SOURCE

#define REQUEST_TIMEOUT 30
#define UPLOAD_TIMEOUT 120
#define DOWNLOAD_TIMEOUT 60


static AFNetworkReachabilityManager *s_hostReach = nil;

static MJReachabilityStatus g_reachableState = MJReachabilityStatusUnknown;

static MJURLSessionDidReceiveChallengeBlock s_sessionDidReceiveChallengeBlock = NULL;

static NSMutableDictionary *s_dicRequest = nil;

static NSMutableDictionary *s_dicHostCheckResult = nil;

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
        
        // 请求缓存字典
        if (!s_dicRequest) {
            s_dicRequest = [[NSMutableDictionary alloc] init];
        }
        
        // 证书验证回调
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
                    if ([strSummary isEqualToString:@"AddTrust External CA Root"]) {
                        // 未知情况导致根证书变更
                        if (certificateCount > 1) {
                            certificate = SecTrustGetCertificateAtIndex(serverTrust, certificateCount-2);
                            strSummaryRef = SecCertificateCopySubjectSummary(certificate);
                            strSummary = (NSString *)CFBridgingRelease(strSummaryRef);
                        }
                    }
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

+ (MJRequestSecurityState)requestSecurityStateOf:(NSString *)serverUrl
{
    if (serverUrl.length == 0) {
        LogError(@"Server url can not be nil");
        return MJRequestSecurityStateUnknown;
    }
    if (![serverUrl hasPrefix:@"https"]) {
        LogError(@"Server url not start with 'https'");
        return MJRequestSecurityStateSecure;
    }
    if (s_dicHostCheckResult == nil) {
        s_dicHostCheckResult = [[NSMutableDictionary alloc] init];
        return MJRequestSecurityStateUnknown;
    }
    NSURL *url = [NSURL URLWithString:serverUrl];
    NSString *hostUrl = [NSString stringWithFormat:@"%@://%@", url.scheme, url.host];
    
    NSMutableDictionary *curCheckResult = [s_dicHostCheckResult objectForKey:hostUrl];
    if (curCheckResult) {
        BOOL securityHaveChecked = [[curCheckResult objectForKey:@"securityHaveChecked"] boolValue];
        MJRequestSecurityState securityState = [[curCheckResult objectForKey:@"securityState"] integerValue];
        if (securityHaveChecked) {
            return securityState;
        }
    }
    return MJRequestSecurityStateUnknown;
}

+ (void)setSesionDidReceiveChallengeBlock:(MJURLSessionDidReceiveChallengeBlock)sesionDidReceiveChallengeBlock
{
    s_sessionDidReceiveChallengeBlock = sesionDidReceiveChallengeBlock;
}

#ifdef FUN_NEED_SECURITY_REQUEST
// 坚持请求是否安全，返回也是表示安装可以继续操作，返回NO，表示未检查完成或不安全
+ (NSString *)checkRequestSecurity:(NSString *)serverUrl completion:(void (^)(MJRequestSecurityState, NSError *))completion
{
    MJRequestSecurityState securityState = MJRequestSecurityStateUnknown;
    if (serverUrl.length == 0) {
        LogError(@"Server url can not be nil");
        NSError *err = [[NSError alloc] initWithDomain:kErrorDomainWebService
                                                  code:-1
                                              userInfo:@{
                                                         NSLocalizedDescriptionKey:locString(sNetworkErrorMsg),
                                                         NSLocalizedFailureReasonErrorKey:locString(sNetworkErrorMsg)
                                                }];
        completion(securityState, err);
        return nil;
    }
    if (![serverUrl hasPrefix:@"https"]) {
        LogError(@"Server url not start with 'https'");
        securityState = MJRequestSecurityStateSecure;
        completion(securityState, nil);
        return nil;
    }
    if (s_dicHostCheckResult == nil) {
        s_dicHostCheckResult = [[NSMutableDictionary alloc] init];
    }
    NSURL *url = [NSURL URLWithString:serverUrl];
    NSString *hostUrl = [NSString stringWithFormat:@"%@://%@", url.scheme, url.host];
    if (url.port && [url.port intValue] != 443) {
        hostUrl = [hostUrl stringByAppendingFormat:@":%@", url.port];
    }
    
    NSMutableDictionary *curCheckResult = [s_dicHostCheckResult objectForKey:hostUrl];
    if (curCheckResult) {
        BOOL securityHaveChecked = [[curCheckResult objectForKey:@"securityHaveChecked"] boolValue];
        securityState = [[curCheckResult objectForKey:@"securityState"] integerValue];
        if (securityHaveChecked) {
            if (securityState != MJRequestSecurityStateSecure) {
                // 这里不回掉的话将没有地方回掉
                NSError *errCheck = [curCheckResult objectForKey:@"errCheck"];
                completion(securityState, errCheck);
            } else {
                completion(securityState, nil);
            }
            return nil;
        }
    } else {
        curCheckResult = [[NSMutableDictionary alloc] init];
        NSMutableArray *arrCheckCompletion = [[NSMutableArray alloc] init];
        [curCheckResult setObject:arrCheckCompletion forKey:@"arrCheckCompletion"];
        [s_dicHostCheckResult setObject:curCheckResult forKey:hostUrl];
    }
    
    NSString *requestId = [[NSUUID UUID] UUIDString];
    [s_dicRequest setObject:completion forKey:requestId];
    
    NSMutableArray *arrCheckCompletion = [curCheckResult objectForKey:@"arrCheckCompletion"];
    
    BOOL isInChek = [[curCheckResult objectForKey:@"isInChek"] boolValue];
    if (isInChek) {
        // 这里只用保存请求ID，s_dicRequest 中 已保存了请求回调
        [arrCheckCompletion addObject:requestId];
        return requestId;
    }
    [curCheckResult setObject:@YES forKey:@"isInChek"];
    
    [curCheckResult setObject:@NO forKey:@"haveCheck"];
    
    void(^requestRespond)(BOOL, NSError *) = ^(BOOL needRecheck, NSError *err) {
        // 是否调用证书检查
        BOOL haveCheck = [[curCheckResult objectForKey:@"haveCheck"] boolValue];
        BOOL securityHaveChecked = YES;
        MJRequestSecurityState securityState = needRecheck?MJRequestSecurityStateUnknown:(haveCheck?MJRequestSecurityStateSecure:MJRequestSecurityStateUnsafe);
        [curCheckResult setObject:[NSNumber numberWithBool:YES] forKey:@"securityHaveChecked"];
        [curCheckResult setObject:[NSNumber numberWithInteger:securityState] forKey:@"securityState"];
        if (securityState != MJRequestSecurityStateSecure && err == nil) {
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
            for (NSString *aRequestId in arrCompletion) {
                void(^aCompletion)(MJRequestSecurityState, NSError *) = [s_dicRequest objectForKey:aRequestId];
                if (aCompletion) {
                    aCompletion(securityState, err);
                    [s_dicRequest removeObjectForKey:aRequestId];
                }
            }
            [arrCheckCompletion removeAllObjects];
        }
        if ([s_dicRequest objectForKey:requestId]) {
            completion(securityState, err);
            [s_dicRequest removeObjectForKey:requestId];
        }
        if (securityState == MJRequestSecurityStateUnknown) {
            securityHaveChecked = NO;
            [curCheckResult removeObjectForKey:@"errCheck"];
        }
        [curCheckResult setObject:[NSNumber numberWithBool:securityHaveChecked] forKey:@"securityHaveChecked"];
    };
    
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    manager.requestSerializer.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    
    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        if ([[curCheckResult objectForKey:@"haveCheck"] boolValue]) {
            return NSURLSessionAuthChallengePerformDefaultHandling;
        }
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
    return requestId;
}
#endif

/// 准备开始安全的网络请求
+ (NSString *)prepareForSecurityRequest:(NSString *)serverUrl sucureCompletion:(NSString * (^)(void))completion failCompletion:(MJResponseBlock)failCompletion
{
    __block NSString *requestId = nil;
    NSString *securityRequestId = [self checkRequestSecurity:serverUrl completion:^(MJRequestSecurityState securityState, NSError *err) {
        
        if (securityState != MJRequestSecurityStateUnknown) {
            // 该请求安全性已确认，可以直接回调
            if (securityState == MJRequestSecurityStateUnsafe) {
                failCompletion ? failCompletion(nil, nil, [self errorForbidden]) : 0;
            } else {
                // 这里开始实际的网络请求调用
                NSString *aRequestId = completion ? completion() : nil;
                if (requestId && [s_dicRequest objectForKey:requestId]) {
                    [s_dicRequest setObject:aRequestId forKey:requestId];
                } else {
                    // 当block立即被调用的时候回到这里，或者请求被中途取消
                    requestId = aRequestId;
                }
            }
            return;
        }
        // 这里的unknown 必然是经过网络请求的，不会是立即调用的
        failCompletion ? failCompletion(nil, nil, err) : 0;
    }];
    if (securityRequestId) {
        requestId = securityRequestId;
    }
    return requestId;
}

#pragma mark - 取消网络请求

+ (void)cancelRequestWith:(NSString *)requestId
{
    id aRequest = [s_dicRequest objectForKey:requestId];
    if (aRequest == nil) {
        return;
    }
    
    // 如果其中包含的是字符串，这里一点是依赖请求的requestId
    if ([aRequest isKindOfClass:[NSString class]]) {
        [self cancelRequestWith:requestId];
    } else if ([aRequest isKindOfClass:[NSURLSessionTask class]]) {
        [(NSURLSessionTask *)aRequest cancel];
    } else {
        void(^aCompletion)(BOOL, NSError *) = aRequest;
        aCompletion(NO, [self errorCanceled]);
    }
    [s_dicRequest removeObjectForKey:requestId];
}


#pragma mark - 发起GET请求

+ (NSString *)startGet:(NSString *)serverUrl
            body:(NSDictionary *)body
      completion:(MJResponseBlock)completion
{
    return [self startGet:serverUrl header:nil body:body completion:completion];
}

+ (NSString *)startGetText:(NSString *)serverUrl
                      body:(NSDictionary *)body
                completion:(MJResponseBlock)completion
{
    return [self startGet:serverUrl header:@{@"textResponse":@YES} body:body completion:completion];
}



+ (NSString *)startGet:(NSString *)serverUrl
                header:(NSDictionary *)header
                  body:(NSDictionary *)body
            completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return nil;
    }
#ifdef FUN_NEED_SECURITY_REQUEST
    NSString *requestId = [self prepareForSecurityRequest:serverUrl sucureCompletion:^NSString *{
        return [self startExecuteGet:serverUrl header:header body:body completion:completion];
    } failCompletion:completion];
    return requestId;
#endif
    return [self startExecuteGet:serverUrl header:header body:body completion:completion];
}

/// 开始执行Get请求，这个方法必须是在确保请求安装的时候调用
+ (NSString *)startExecuteGet:(NSString *)serverUrl
                       header:(NSDictionary *)header
                         body:(NSDictionary *)body
                   completion:(MJResponseBlock)completion
{
    NSString *requestId = [[NSUUID UUID] UUIDString];
    // 拼接请求url
    NSString *pathUrl = [serverUrl stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager = [self managerWithHeader:header];
    
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    
    NSURLSessionDataTask *dataTask = [manager GET:pathUrl parameters:body progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
        [s_dicRequest removeObjectForKey:requestId];
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
        [s_dicRequest removeObjectForKey:requestId];
    }];
    [s_dicRequest setObject:dataTask forKey:requestId];
    return requestId;
}

#pragma mark - 发起POST请求

+ (NSString *)startPost:(NSString *)serverUrl
                   body:(NSDictionary *)body
             completion:(MJResponseBlock)completion
{
    return [self startPost:serverUrl header:nil body:body completion:completion];
}

+ (NSString *)startPost:(NSString *)serverUrl
                 header:(NSDictionary *)header
                   body:(NSDictionary *)body
             completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return nil;
    }
#ifdef FUN_NEED_SECURITY_REQUEST
    NSString *requestId = [self prepareForSecurityRequest:serverUrl sucureCompletion:^NSString *{
        return [self startExecutePost:serverUrl header:header body:body completion:completion];
    } failCompletion:completion];
    return requestId;
#endif
    return [self startExecutePost:serverUrl header:header body:body completion:completion];
}

+ (NSString *)startExecutePost:(NSString *)serverUrl
                        header:(NSDictionary *)header
                          body:(NSDictionary *)body
                    completion:(MJResponseBlock)completion
{
    NSString *requestId = [[NSUUID UUID] UUIDString];
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager = [self managerWithHeader:header];
    
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    
    NSURLSessionDataTask *dataTask = [manager POST:pathUrl parameters:body progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
        [s_dicRequest removeObjectForKey:requestId];
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
        [s_dicRequest removeObjectForKey:requestId];
    }];
    [s_dicRequest setObject:dataTask forKey:requestId];
    return requestId;
}

#pragma mark - 发起Put请求

+ (NSString *)startPut:(NSString *)serverUrl
                  body:(NSDictionary *)body
            completion:(MJResponseBlock)completion
{
    return [self startPut:serverUrl header:nil body:body completion:completion];
}

+ (NSString *)startPut:(NSString *)serverUrl
                header:(NSDictionary *)header
                  body:(NSDictionary *)body
            completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return nil;
    }
#ifdef FUN_NEED_SECURITY_REQUEST
    NSString *requestId = [self prepareForSecurityRequest:serverUrl sucureCompletion:^NSString *{
        return [self startExecutPut:serverUrl header:header body:body completion:completion];
    } failCompletion:completion];
    return requestId;
#endif
    return [self startExecutPut:serverUrl header:header body:body completion:completion];
}

+ (NSString *)startExecutPut:(NSString *)serverUrl
                      header:(NSDictionary *)header
                        body:(NSDictionary *)body
                  completion:(MJResponseBlock)completion
{
    NSString *requestId = [[NSUUID UUID] UUIDString];
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager = [self managerWithHeader:header];
    
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    
    NSURLSessionDataTask *dataTask = [manager PUT:pathUrl parameters:body success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
        [s_dicRequest removeObjectForKey:requestId];
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
        [s_dicRequest removeObjectForKey:requestId];
    }];
    [s_dicRequest setObject:dataTask forKey:requestId];
    return requestId;
}

#pragma mark - 发起Delete请求

+ (NSString *)startDelete:(NSString *)serverUrl
                     body:(NSDictionary *)body
               completion:(MJResponseBlock)completion
{
    return [self startDelete:serverUrl header:nil body:body completion:completion];
}

+ (NSString *)startDelete:(NSString *)serverUrl
                   header:(NSDictionary *)header
                     body:(NSDictionary *)body
               completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return nil;
    }
#ifdef FUN_NEED_SECURITY_REQUEST
    NSString *requestId = [self prepareForSecurityRequest:serverUrl sucureCompletion:^NSString *{
        return [self startExecuteDelete:serverUrl header:header body:body completion:completion];
    } failCompletion:completion];
    return requestId;
#endif
    return [self startExecuteDelete:serverUrl header:header body:body completion:completion];
}

+ (NSString *)startExecuteDelete:(NSString *)serverUrl
                          header:(NSDictionary *)header
                            body:(NSDictionary *)body
                      completion:(MJResponseBlock)completion
{
    NSString *requestId = [[NSUUID UUID] UUIDString];
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestBody: %@\n", body);
    
    AFHTTPSessionManager *manager = [self managerWithHeader:header];
    
    [manager.requestSerializer setTimeoutInterval:REQUEST_TIMEOUT];
    
    NSURLSessionDataTask *dataTask = [manager DELETE:pathUrl parameters:body success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        // 请求成功
        LogDebug(@"...>>>...receiveData = %@", responseObject);
        completion ? completion(task.response, responseObject, nil) : 0;
        [s_dicRequest removeObjectForKey:requestId];
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
        [s_dicRequest removeObjectForKey:requestId];
    }];
    [s_dicRequest setObject:dataTask forKey:requestId];
    return requestId;
}



#pragma mark - 发起Upload请求

/** 多文件上传 */
+ (NSString *)startUploadFiles:(NSString *)serverUrl
                    body:(NSDictionary *)body
                   files:(NSArray *)files
              completion:(MJResponseBlock)completion
{
    return [self startUploadFiles:serverUrl header:nil body:body files:files completion:completion];
}

+ (NSString *)startUploadFiles:(NSString *)serverUrl
                  header:(NSDictionary *)header
                    body:(NSDictionary *)body
                   files:(NSArray *)files
              completion:(MJResponseBlock)completion
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return nil;
    }
#ifdef FUN_NEED_SECURITY_REQUEST
    NSString *requestId = [self prepareForSecurityRequest:serverUrl sucureCompletion:^NSString *{
        return [self startExecuteUploadFiles:serverUrl header:header body:body files:files completion:completion];
    } failCompletion:completion];
    return requestId;
#endif
    return [self startExecuteUploadFiles:serverUrl header:header body:body files:files completion:completion];
}

+ (NSString *)startExecuteUploadFiles:(NSString *)serverUrl
                               header:(NSDictionary *)header
                                 body:(NSDictionary *)body
                                files:(NSArray *)files
                           completion:(MJResponseBlock)completion
{
    NSString *requestId = [[NSUUID UUID] UUIDString];
    // 拼接请求url
    NSString *pathUrl = serverUrl;
    LogTrace(@"...>>>...requestUrl: %@\n", pathUrl);
    LogDebug(@"...>>>...requestData: %@\n", body);
    
    AFHTTPSessionManager *manager = [self managerWithHeader:header];
    
    [manager.requestSerializer setTimeoutInterval:UPLOAD_TIMEOUT];
    
    NSURLSessionDataTask *dataTask = [manager POST:pathUrl parameters:body constructingBodyWithBlock:^(id<AFMultipartFormData>  _Nonnull formData) {
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
        [s_dicRequest removeObjectForKey:requestId];
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        // 请求失败
        LogError(@"...>>>...Network error: %@ %@\n", serverUrl, error.localizedDescription);
        completion ? completion(task.response, nil, error) : 0;
        [s_dicRequest removeObjectForKey:requestId];
    }];
    [s_dicRequest setObject:dataTask forKey:requestId];
    return requestId;
    
}


#pragma mark - 发起Download请求

/** 单个文件下载 */
+ (NSString *)startDownload:(NSString *)remotePath
                               withSavePath:(NSString *)localPath
                                 completion:(MJResponseBlock)completion
                              progressBlock:(void (^)(NSUInteger bytesRead, long long totalBytesRead, long long totalBytesExpectedToRead))progressBlock
{
    return [self startDownload:remotePath header:nil body:nil withSavePath:localPath completion:completion progressBlock:progressBlock];
}

+ (NSString *)startDownload:(NSString *)remotePath
                                     header:(NSDictionary *)header
                                       body:(NSDictionary *)body
                               withSavePath:(NSString *)localPath
                                 completion:(MJResponseBlock)completion
                              progressBlock:(void (^)(NSUInteger bytesRead, long long totalBytesRead, long long totalBytesExpectedToRead))progressBlock
{
    [self dataInit];
    if (g_reachableState == AFNetworkReachabilityStatusNotReachable) {
        completion ? completion(nil, nil, [self errorOffNet]) : 0;
        return nil;
    }
    
#ifdef FUN_NEED_SECURITY_REQUEST
    NSString *requestId = [self prepareForSecurityRequest:remotePath sucureCompletion:^NSString *{
        return [self startExecuteDownload:remotePath header:header body:body withSavePath:localPath completion:completion progressBlock:progressBlock];
    } failCompletion:completion];
    return requestId;
#endif
    return [self startExecuteDownload:remotePath header:header body:body withSavePath:localPath completion:completion progressBlock:progressBlock];
}

+ (NSString *)startExecuteDownload:(NSString *)remotePath
                            header:(NSDictionary *)header
                              body:(NSDictionary *)body
                      withSavePath:(NSString *)localPath
                        completion:(MJResponseBlock)completion
                     progressBlock:(void (^)(NSUInteger bytesRead, long long totalBytesRead, long long totalBytesExpectedToRead))progressBlock
{
    NSString *requestId = [[NSUUID UUID] UUIDString];
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
    NSString *filePathTemp = [NSString stringWithFormat:@"%@.temp-%@",localPath, requestId];   //临时下载的文件路径
    
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
            [s_dicRequest removeObjectForKey:requestId];
        });
    }];
    [s_dicRequest setObject:downloadTask forKey:requestId];
    [downloadTask resume];
    return requestId;
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

+ (NSError *)errorCanceled
{
    static NSError *err;
    if (err == nil) {
        err = [[NSError alloc] initWithDomain:kErrorDomainWebService
                                         code:sNetworkCodeCanceled
                                     userInfo:@{
                                                NSLocalizedDescriptionKey:locString(sNetworkCanceled),
                                                NSLocalizedFailureReasonErrorKey:locString(sNetworkCanceled)
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
    // 证书信任统一处理
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession * _Nonnull session, NSURLAuthenticationChallenge * _Nonnull challenge, NSURLCredential *__autoreleasing  _Nullable * _Nullable credential) {
        return s_sessionDidReceiveChallengeBlock(nil, session, challenge, credential);
    }];
    return manager;
}

@end
