/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

#import "Security.h"
#import <Cordova/CDV.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>
#import "GTMBase64.h"
#define IV @"0102030405060708"

@implementation Security

- (void)aesEncrypt:(CDVInvokedUrlCommand*)command
{
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        NSString *text = (NSString *)[command argumentAtIndex:0];
        if(text == nil){
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Arg was null"];
        } else {
            NSString *key = (NSString *)[command argumentAtIndex:1];
            NSData *srcData = [text dataUsingEncoding: NSUTF8StringEncoding];
            
            char keyPtr[kCCKeySizeAES128+1];
            bzero(keyPtr, sizeof(keyPtr));
            [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
            
            NSUInteger dataLength = [srcData length];
            size_t bufferSize = dataLength + kCCBlockSizeAES128;
            void *buffer = malloc(bufferSize);
            size_t numBytesEncrypted = 0;
            
            char ivPtr[kCCKeySizeAES128+1];
            memset(ivPtr, 0, sizeof(ivPtr));
            [IV getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
            
            CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128,
                                                  kCCOptionPKCS7Padding | kCCOptionECBMode,
                                                  keyPtr, kCCBlockSizeAES128,
                                                  ivPtr,
                                                  [srcData bytes], dataLength,
                                                  buffer, bufferSize,
                                                  &numBytesEncrypted);
            if (cryptStatus == kCCSuccess) {
                NSData *data = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
                NSString *aString = [GTMBase64 stringByEncodingData:data];
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:aString];
            }else{
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"加密失败"];
                free(buffer);
            }
        }
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)aesDecrypt:(CDVInvokedUrlCommand*)command
{
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        NSString *text = (NSString *)[command argumentAtIndex:0];
        if(text == nil){
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Arg was null"];
        } else {
            NSString *key = (NSString *)[command argumentAtIndex:1];
            NSData *cryptData = [GTMBase64 decodeString:text];
            
            char keyPtr[kCCKeySizeAES128+1];
            bzero(keyPtr, sizeof(keyPtr));
            [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
            NSUInteger dataLength = [cryptData length];
            size_t bufferSize = dataLength + kCCBlockSizeAES128;
            void *buffer = malloc(bufferSize);
            size_t numBytesDecrypted = 0;
            
            char ivPtr[kCCKeySizeAES128+1];
            memset(ivPtr, 0, sizeof(ivPtr));
            [IV getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
            
            CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                                  kCCOptionPKCS7Padding | kCCOptionECBMode,
                                                  keyPtr, kCCBlockSizeAES128,
                                                  ivPtr,
                                                  [cryptData bytes], dataLength,
                                                  buffer, bufferSize,
                                                  &numBytesDecrypted);
            if (cryptStatus == kCCSuccess) {
                NSData *data = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
                NSString *aString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:aString];
            }else{
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"解密失败"];
                free(buffer);
            }
        }
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)encrypt:(CDVInvokedUrlCommand*)command
{
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        NSString *text = (NSString *)[command argumentAtIndex:0];
        if(text == nil){
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Arg was null"];
        } else {
            NSString *key = (NSString *)[command argumentAtIndex:1];
            NSData *dkey = [GTMBase64 decodeString:key];
            
            NSData *srcData = [text dataUsingEncoding: NSUTF8StringEncoding];
            NSUInteger dataLength = [srcData length];
            size_t bufferSize = dataLength + kCCBlockSizeAES128;
            void *buffer = malloc(bufferSize);
            size_t numBytesEncrypted = 0;
            
            char ivPtr[kCCKeySizeAES128+1];
            memset(ivPtr, 0, sizeof(ivPtr));
            [IV getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
            
            CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128,
                                                  kCCOptionPKCS7Padding | kCCOptionECBMode,
                                                  [dkey bytes], kCCBlockSizeAES128,
                                                  ivPtr,
                                                  [srcData bytes], dataLength,
                                                  buffer, bufferSize,
                                                  &numBytesEncrypted);
            if (cryptStatus == kCCSuccess) {
                NSData *data = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
                NSString *aString = [GTMBase64 stringByEncodingData:data];
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:aString];
            }else{
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"加密失败"];
                free(buffer);
            }
        }
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)decrypt:(CDVInvokedUrlCommand*)command
{
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        NSString *text = (NSString *)[command argumentAtIndex:0];
        if(text == nil){
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Arg was null"];
        } else {
            NSString *key = (NSString *)[command argumentAtIndex:1];
            NSData *dkey = [GTMBase64 decodeString:key];
            
            NSData *cryptData = [GTMBase64 decodeString:text];
            NSUInteger dataLength = [cryptData length];
            size_t bufferSize = dataLength + kCCBlockSizeAES128;
            void *buffer = malloc(bufferSize);
            size_t numBytesDecrypted = 0;
            
            char ivPtr[kCCKeySizeAES128+1];
            memset(ivPtr, 0, sizeof(ivPtr));
            [IV getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
            
            CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                                  kCCOptionPKCS7Padding | kCCOptionECBMode,
                                                  [dkey bytes], kCCBlockSizeAES128,
                                                  ivPtr,
                                                  [cryptData bytes], dataLength,
                                                  buffer, bufferSize,
                                                  &numBytesDecrypted);
            if (cryptStatus == kCCSuccess) {
                NSData *data = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
                NSString *aString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:aString];
            }else{
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"解密失败"];
                free(buffer);
            }   
        }
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

@end
