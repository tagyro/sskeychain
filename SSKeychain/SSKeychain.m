//
//  SSKeychain.m
//  SSToolkit
//
//  Created by Sam Soffes on 5/19/10.
//  Copyright (c) 2009-2011 Sam Soffes. All rights reserved.
//

#import "SSKeychain.h"

NSString *const kSSKeychainErrorDomain = @"com.samsoffes.sskeychain";

NSString *const kSSKeychainAccountKey = @"acct";
NSString *const kSSKeychainCreatedAtKey = @"cdat";
NSString *const kSSKeychainClassKey = @"labl";
NSString *const kSSKeychainDescriptionKey = @"desc";
NSString *const kSSKeychainLabelKey = @"labl";
NSString *const kSSKeychainLastModifiedKey = @"mdat";
NSString *const kSSKeychainWhereKey = @"svce";

#if __IPHONE_4_0 && TARGET_OS_IPHONE  
CFTypeRef SSKeychainAccessibilityType = NULL;
#endif

@interface SSKeychain ()
+ (NSMutableDictionary *)_queryForService:(NSString *)service account:(NSString *)account;
@end

@implementation SSKeychain

#pragma mark - Getting Accounts

+ (NSArray *)allAccounts {
    return [self accountsForService:nil error:nil];
}


+ (NSArray *)allAccounts:(NSError **)error {
    return [self accountsForService:nil error:error];
}


+ (NSArray *)accountsForService:(NSString *)service {
    return [self accountsForService:service error:nil];
}


+ (NSArray *)accountsForService:(NSString *)service error:(NSError **)error {
    OSStatus status = SSKeychainErrorBadArguments;
    NSMutableDictionary *query = [self _queryForService:service account:nil];
#if __has_feature(objc_arc)
	query[(__bridge id)kSecReturnAttributes] = (__bridge id)kCFBooleanTrue;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
#else
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnAttributes];
    [query setObject:(id)kSecMatchLimitAll forKey:(id)kSecMatchLimit];
#endif
	
	CFTypeRef result = NULL;
#if __has_feature(objc_arc)
    status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
#else
	status = SecItemCopyMatching((CFDictionaryRef)query, &result);
#endif
    if (status != noErr && error != NULL) {
		*error = [NSError errorWithDomain:kSSKeychainErrorDomain code:status userInfo:nil];
		return nil;
	}
	
#if __has_feature(objc_arc)
	return (__bridge_transfer NSArray *)result;
#else
    return [(NSArray *)result autorelease];
#endif
}


#pragma mark - Getting Passwords

+ (NSString *)passwordForService:(NSString *)service account:(NSString *)account {
	return [self passwordForService:service account:account error:nil];
}


+ (NSString *)passwordForService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    NSData *data = [self passwordDataForService:service account:account error:error];
	if (data.length > 0) {
		NSString *string = [[NSString alloc] initWithData:(NSData *)data encoding:NSUTF8StringEncoding];
#if !__has_feature(objc_arc)
		[string autorelease];
#endif
		return string;
	}
	
	return nil;
}


+ (NSData *)passwordDataForService:(NSString *)service account:(NSString *)account {
    return [self passwordDataForService:service account:account error:nil];
}


+ (NSData *)passwordDataForService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    OSStatus status = SSKeychainErrorBadArguments;
	if (!service || !account) {
		if (error) {
			*error = [NSError errorWithDomain:kSSKeychainErrorDomain code:status userInfo:nil];
		}
		return nil;
	}
	
	CFTypeRef result = NULL;	
	NSMutableDictionary *query = [self _queryForService:service account:account];
#if __has_feature(objc_arc)
	query[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
	query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
	status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
#else
	[query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
	[query setObject:(id)kSecMatchLimitOne forKey:(id)kSecMatchLimit];
	status = SecItemCopyMatching((CFDictionaryRef)query, &result);
#endif
	
	if (status != noErr && error != NULL) {
		*error = [NSError errorWithDomain:kSSKeychainErrorDomain code:status userInfo:nil];
		return nil;
	}
	
#if __has_feature(objc_arc)
	return (__bridge_transfer NSData *)result;
#else
    return [(NSData *)result autorelease];
#endif
}


#pragma mark - Deleting Passwords

+ (BOOL)deletePasswordForService:(NSString *)service account:(NSString *)account {
	return [self deletePasswordForService:service account:account error:nil];
}


+ (BOOL)deletePasswordForService:(NSString *)service account:(NSString *)account error:(NSError **)error {
	OSStatus status = SSKeychainErrorBadArguments;
	if (service && account) {
		NSMutableDictionary *query = [self _queryForService:service account:account];
#if __has_feature(objc_arc)
		status = SecItemDelete((__bridge CFDictionaryRef)query);
#else
		status = SecItemDelete((CFDictionaryRef)query);
#endif
	}
	if (status != noErr && error != NULL) {
		*error = [NSError errorWithDomain:kSSKeychainErrorDomain code:status userInfo:nil];
	}
	return (status == noErr);
    
}


#pragma mark - Setting Passwords

+ (BOOL)setPassword:(NSString *)password forService:(NSString *)service account:(NSString *)account {
	return [self setPassword:password forService:service account:account error:nil];
}


+ (BOOL)setPassword:(NSString *)password forService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    return [self setPasswordData:data forService:service account:account error:error];
}


+ (BOOL)setPasswordData:(NSData *)password forService:(NSString *)service account:(NSString *)account {
    return [self setPasswordData:password forService:service account:account error:nil];
}


+ (BOOL)setPasswordData:(NSData *)password forService:(NSString *)service account:(NSString *)account error:(NSError **)error {
    OSStatus status = SSKeychainErrorBadArguments;
	if (password && service && account) {
        [self deletePasswordForService:service account:account];
        NSMutableDictionary *query = [self _queryForService:service account:account];
#if __has_feature(objc_arc)
		query[(__bridge id)kSecValueData] = password;
#else
		[query setObject:password forKey:(id)kSecValueData];
#endif
		
#if __IPHONE_4_0 && TARGET_OS_IPHONE
		if (SSKeychainAccessibilityType) {
#if __has_feature(objc_arc)
			query[(__bridge id)kSecAttrAccessible] = (id)[self accessibilityType];
#else
			[query setObject:(id)[self accessibilityType] forKey:(id)kSecAttrAccessible];
#endif
		}
#endif
		
#if __has_feature(objc_arc)
        status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
#else
		status = SecItemAdd((CFDictionaryRef)query, NULL);
#endif
	}
	if (status != noErr && error != NULL) {
		*error = [NSError errorWithDomain:kSSKeychainErrorDomain code:status userInfo:nil];
	}
	return (status == noErr);
}


#pragma mark - Configuration

#if __IPHONE_4_0 && TARGET_OS_IPHONE 
+ (CFTypeRef)accessibilityType {
	return SSKeychainAccessibilityType;
}


+ (void)setAccessibilityType:(CFTypeRef)accessibilityType {
	CFRetain(accessibilityType);
	if (SSKeychainAccessibilityType) {
		CFRelease(SSKeychainAccessibilityType);
	}
	SSKeychainAccessibilityType = accessibilityType;
}
#endif


#pragma mark - Private

+ (NSMutableDictionary *)_queryForService:(NSString *)service account:(NSString *)account {
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionaryWithCapacity:3];
#if __has_feature(objc_arc)
    dictionary[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
#else
	[dictionary setObject:(id)kSecClassGenericPassword forKey:(id)kSecClass];
#endif
	
    if (service) {
#if __has_feature(objc_arc)
		dictionary[(__bridge id)kSecAttrService] = service;
#else
		[dictionary setObject:service forKey:(id)kSecAttrService];
#endif
	}
	
    if (account) {
#if __has_feature(objc_arc)
		dictionary[(__bridge id)kSecAttrAccount] = account;
#else
		[dictionary setObject:account forKey:(id)kSecAttrAccount];
#endif
	}
	
    return dictionary;
}

#pragma mark Custom methods

+(NSString*)checkCredentialsForUsername:(NSString*)username {
    NSArray *credentials = [SSKeychain accountsForService:kServiceName];
    if (credentials.count>=1) {
        for (int i=0;i<credentials.count;i++) {
            NSDictionary *account = credentials[i];
            if ([[account valueForKey:@"acct"] isEqualToString:username]) {
                return [SSKeychain passwordForService:kServiceName account:username];
            }
        }
        if ([SSKeychain passwordForService:kServiceName account:username]) {
            return [SSKeychain passwordForService:kServiceName account:username];
            //loginButton.enabled = YES;
        }
    } else {
        ////NSLog(@"no account for this service %i",credentials.count);
    }
    //
    return @"";
}

+(void)saveCredentials:(NSString*)username pass:(NSString*)password {
    ////NSLog(@"saved credentials: %@ | %@",username, password);
    [SSKeychain setPassword:password forService:kServiceName account:username];
}

+(void)clearCredentialsForUsername:(NSString*)username {
    NSArray *credentials = [SSKeychain accountsForService:kServiceName];
    for (int i=0;i<credentials.count;i++) {
        [SSKeychain deletePasswordForService:kServiceName account:[credentials[i] valueForKey:@"acct"]];
    }
}

@end
