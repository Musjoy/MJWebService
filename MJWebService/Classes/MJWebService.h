//
//  MJWebService.h
//  Common
//
//  Created by 黄磊 on 16/4/6.
//  Copyright © 2016年 Musjoy. All rights reserved.
//  网络请求类<MODULE_WEB_SERVICE>

#import <Foundation/Foundation.h>

#ifndef FILE_NAME_CER_TRUST_LIST
#define FILE_NAME_CER_TRUST_LIST    @"cer_trust_list"
#endif

#ifndef SERVER_CER_TRUST_LIST
/// 默认证书信任列表
#define SERVER_CER_TRUST_LIST       @[\
@"VeriSign Class 3 Public Primary Certification Authority - G5",\
@"DST Root CA X3",\
@"GeoTrust Global CA",\
@"DigiCert High Assurance EV Root CA",\
@"GlobalSign Root CA",\
@"GeoTrust Primary Certification Authority",\
@"StartCom Certification Authority",\
@"Go Daddy Root Certificate Authority - G2",\
@"Baltimore CyberTrust Root",\
@"DigiCert Global Root CA",\
@"COMODO ECC Certification Authority"\
]
#endif

// 定义该宏定义来开启安全请求，默认开启
#if defined(FUN_NEED_SECURITY_REQUEST) && !FUN_NEED_SECURITY_REQUEST
#undef FUN_NEED_SECURITY_REQUEST
#else
#define FUN_NEED_SECURITY_REQUEST
#endif
//#define FUN_NEED_SECURITY_REQUEST

// 通知
/// 网络状态变化通知
static NSString *const kNoticReachabilityChange = @"NoticReachabilityChange";
/// 网络可用通知
static NSString *const kNoticGetNetwork         = @"NoticGetNetwork";
/// 失去网络通知
static NSString *const kNoticLoseNetwork        = @"NoticLoseNetwork";

/// 错误域
static NSString *const kErrorDomainWebService   = @"WebService";

#define sNetworkCodeOffNet          -10000
#define sNetworkCodeForbidden       -20000
#define sNetworkCodeCanceled        -30000
// 相关提示文字
#define sNetworkErrorMsg            @"Network Error"
#define sNetworkUnreachMsg          @"Network Unreachable"
#define sNetworkForbidden           @"Network Forbidden"
#define sNetworkCanceled            @"Request Canceled"

#ifndef STAT_DOMAIN_ROOT_CA
#define STAT_DOMAIN_ROOT_CA    @"DomainRootCA"
#endif


typedef NSURLSessionAuthChallengeDisposition (^MJURLSessionDidReceiveChallengeBlock)(NSString *domain, NSURLSession *session, NSURLAuthenticationChallenge *challenge, NSURLCredential * __autoreleasing *credential);

typedef NS_ENUM(NSInteger, MJReachabilityStatus) {
    MJReachabilityStatusUnknown             = -1,
    MJReachabilityStatusNotReachable        = 0,
    MJReachabilityStatusReachableViaWWAN    = 1,
    MJReachabilityStatusReachableViaWiFi    = 2,
};

typedef NS_ENUM(NSInteger, MJRequestSecurityState) {
    MJRequestSecurityStateUnsafe            = -1,
    MJRequestSecurityStateUnknown           = 0,
    MJRequestSecurityStateSecure            = 1,
};

/// Returns a localized string representation of an `MJReachabilityStatus` value.
FOUNDATION_EXPORT NSString * MJStringFromReachabilityStatus(MJReachabilityStatus status);


typedef void (^MJResponseBlock)(NSURLResponse *response, id responseData, NSError *error);

// 操作成功（网络请求成功，返回值Success = true,两个条件同时成立，才会回调该方法）
typedef void (^RequestSuccessBlock)(id respond);
// 操作失败（网络原因的失败，或者返回值Success != true则执行下面的回调）
typedef void (^RequestFailureBlock)(NSError *error);


@interface MJWebService : NSObject

+ (void)dataInit;

/// 当前网络状态
+ (MJReachabilityStatus)reachableState;

/// 当前请求安全性 暂时去掉
//+ (MJRequestSecurityState)requestSecurityStateOf:(NSString *)serverUrl;

/// 请求时的证书验证回调
+ (void)setSesionDidReceiveChallengeBlock:(MJURLSessionDidReceiveChallengeBlock)sesionDidReceiveChallengeBlock;

// 检查链接是否安全
+ (NSString *)checkRequestSecurity:(NSString *)serverUrl completion:(void(^)(MJRequestSecurityState securityState, NSError *err))completion;

// 取消一个网络请求
+ (void)cancelRequestWith:(NSString *)requestId;

/**
 *  @brief  Get请求接口
 *
 *  @param  serverUrl       接口服务地址
 *  @param  body            请求的body数据
 *  @param  completion      请求完成回调
 *
 *  @return NSString        requestId, 返回请求ID，用于取消请求
 */
+ (NSString *)startGet:(NSString *)serverUrl
                  body:(NSDictionary *)body
            completion:(MJResponseBlock)completion;

+ (NSString *)startGetText:(NSString *)serverUrl
                      body:(NSDictionary *)body
                completion:(MJResponseBlock)completion;

+ (NSString *)startGet:(NSString *)serverUrl
                header:(NSDictionary *)header
                  body:(NSDictionary *)body
            completion:(MJResponseBlock)completion;

/**
 *	@brief	post请求接口
 *
 *	@param  serverUrl       接口服务地址
 *	@param 	body            请求的body数据
 *	@param 	completion      请求完成回调
 *
 *  @return NSString        requestId, 返回请求ID，用于取消请求
 */
+ (NSString *)startPost:(NSString *)serverUrl
                   body:(NSDictionary *)body
             completion:(MJResponseBlock)completion;

+ (NSString *)startPost:(NSString *)serverUrl
                 header:(NSDictionary *)header
                   body:(NSDictionary *)body
             completion:(MJResponseBlock)completion;

+ (NSString *)startPut:(NSString *)serverUrl
                  body:(NSDictionary *)body
            completion:(MJResponseBlock)completion;

+ (NSString *)startPut:(NSString *)serverUrl
                header:(NSDictionary *)header
                  body:(NSDictionary *)body
            completion:(MJResponseBlock)completion;

+ (NSString *)startDelete:(NSString *)serverUrl
                     body:(NSDictionary *)body
               completion:(MJResponseBlock)completion;

+ (NSString *)startDelete:(NSString *)serverUrl
                   header:(NSDictionary *)header
                     body:(NSDictionary *)body
               completion:(MJResponseBlock)completion;
/**
 *	@brief	多文件上传接口
 *
 *	@param 	serverUrl       接口服务地址
 *	@param 	body            请求body数据
 *	@param 	files           请求文件列表，eg：@[@"本地文件全路径", @"本地文件全路径"]
 *	@param 	completion      请求完成回调
 *
 *  @return NSString        requestId, 返回请求ID，用于取消请求
 */
+ (NSString *)startUploadFiles:(NSString *)serverUrl
                          body:(NSDictionary *)body
                         files:(NSArray *)files
                    completion:(MJResponseBlock)completion;

+ (NSString *)startUploadFiles:(NSString *)serverUrl
                        header:(NSDictionary *)header
                          body:(NSDictionary *)body
                         files:(NSArray *)files
                    completion:(MJResponseBlock)completion;

/**
 *	@brief	单个文件下载
 *
 *	@param 	remotePath      下载文件的远程路径
 *	@param 	localPath       下载文件的本地保存路径
 *	@param 	completion      请求完成的回调, respondOrErr: 成功是为NSURLResponse，失败为NSError或nil
 *	@param 	progressBlock 	下载进度回调: bytesRead-已读子节; totalBytesRead-总字节; totalBytesExpectedToRead-未读子节
 *
 *  @return NSString        requestId, 返回请求ID，用于取消请求
 */
+ (NSString *)startDownload:(NSString *)remotePath
               withSavePath:(NSString *)localPath
                 completion:(MJResponseBlock)completion
              progressBlock:(void (^)(NSUInteger bytesRead, long long totalBytesRead, long long totalBytesExpectedToRead))progressBlock;

+ (NSString *)startDownload:(NSString *)remotePath
                     header:(NSDictionary *)header
                       body:(NSDictionary *)body
               withSavePath:(NSString *)localPath
                 completion:(MJResponseBlock)completion
              progressBlock:(void (^)(NSUInteger bytesRead, long long totalBytesRead, long long totalBytesExpectedToRead))progressBlock;

@end
