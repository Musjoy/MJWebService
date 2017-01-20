//
//  MJWebService.h
//  Common
//
//  Created by 黄磊 on 16/4/6.
//  Copyright © 2016年 Musjoy. All rights reserved.
//  网络请求类<MODULE_WEB_SERVICE>

#import <Foundation/Foundation.h>
#import "AFHTTPSessionManager.h"
#import "AFNetworkReachabilityManager.h"


// 通知
/// 网络状态变化通知
static NSString *const kNoticReachabilityChange = @"NoticReachabilityChange";
/// 网络可用通知
static NSString *const kNoticGetNetwork         = @"NoticGetNetwork";
/// 失去网络通知
static NSString *const kNoticLoseNetwork        = @"NoticLoseNetwork";

/// 错误域
static NSString *const kErrorDomain             = @"WebService";

#define sNetworkOffNet              -10000
// 相关提示文字
#define sNetworkUnreachMsg          @"Network Unreachable"
#define sNetworkErrorMsg            @"Network Error"



//操作成功（网络请求成功，返回值Success = true,两个条件同时成立，才会回调该方法）
typedef void (^RequestSuccessBlock)(id respond);
//操作失败（网络原因的失败，或者返回值Success != true则执行下面的回调）
typedef void (^RequestFailureBlock)(NSError *error);


@interface MJWebService : NSObject

+ (void)dataInit;

+ (AFNetworkReachabilityStatus)reachableState;

+ (BOOL)startGet:(NSString *)serverUrl
            body:(NSDictionary *)body
         success:(RequestSuccessBlock)sblock
         failure:(RequestFailureBlock)fblock;

+ (BOOL)startGetText:(NSString *)serverUrl
                body:(NSDictionary *)body
             success:(RequestSuccessBlock)sblock
             failure:(RequestFailureBlock)fblock;

/**
 *	@brief	post请求接口
 *
 *	@param 	serverUrl       接口服务地址
 *	@param 	body            请求的body数据
 *	@param 	returnClass 	就收返回数据的model
 *	@param 	sblock          请求成功回调
 *	@param 	fblock          请求失败回调
 *
 *	@return	void
 */
+ (BOOL)startPost:(NSString *)serverUrl
             body:(NSDictionary *)body
          success:(RequestSuccessBlock)sblock
          failure:(RequestFailureBlock)fblock;

+ (BOOL)startPut:(NSString *)serverUrl
            body:(NSDictionary *)body
         success:(RequestSuccessBlock)sblock
         failure:(RequestFailureBlock)fblock;

+ (BOOL)startDelete:(NSString *)serverUrl
               body:(NSDictionary *)body
            success:(RequestSuccessBlock)sblock
            failure:(RequestFailureBlock)fblock;
/**
 *	@brief	多文件上传接口
 *
 *	@param 	serverUrl       接口服务地址
 *	@param 	body            请求body数据
 *	@param 	files           请求文件列表，eg：@[@"本地文件全路径", @"本地文件全路径"]
 *	@param 	returnClass 	接收返回数据的model
 *	@param 	sblock          成功回调
 *	@param 	fblock          失败回调
 *
 *	@return	void
 */
+ (BOOL)startUploadFiles:(NSString *)serverUrl
                    body:(NSDictionary *)body
                   files:(NSArray *)files
                 success:(RequestSuccessBlock)sblock
                 failure:(RequestFailureBlock)fblock;

/**
 *	@brief	单个文件下载
 *
 *	@param 	remotePath      下载文件的远程路径
 *	@param 	localPath       下载文件的本地保存路径
 *	@param 	completion      请求完成的回调
 *	@param 	progressBlock 	下载进度回调: bytesRead-已读子节; totalBytesRead-总字节; totalBytesExpectedToRead-未读子节
 *
 *	@return	void
 */
+ (void)startDownload:(NSString *)remotePath
         withSavePath:(NSString *)localPath
           completion:(void (^)(BOOL isSucceed, NSString *message))completion
        progressBlock:(void (^)(NSUInteger bytesRead, long long totalBytesRead, long long totalBytesExpectedToRead))progressBlock;



@end
