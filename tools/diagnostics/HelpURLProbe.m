#import <Foundation/Foundation.h>

// Read-only reproduction of the installation-help URL on the running OS.
// No networking, app-container access, account access or installation.
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *raw = @"https://github.com/mengangs/ipadn#安装下载的应用";
        NSString *encoded = @"https://github.com/mengangs/ipadn#%E5%AE%89%E8%A3%85%E4%B8%8B%E8%BD%BD%E7%9A%84%E5%BA%94%E7%94%A8";
        NSURL *original = [NSURL URLWithString:raw];
        NSURL *fixed = [NSURL URLWithString:encoded];
        NSURLComponents *components = [NSURLComponents componentsWithString:@"https://github.com/mengangs/ipadn"];
        components.fragment = @"安装下载的应用";
        BOOL componentOK = components.URL != nil && [components.URL.absoluteString isEqualToString:encoded];
        BOOL sourceOK = YES;
        if (argc == 2) {
            NSString *source = [NSString stringWithContentsOfFile:[NSString stringWithUTF8String:argv[1]] encoding:NSUTF8StringEncoding error:nil];
            NSString *expected = [NSString stringWithFormat:@"Link(\"安装帮助\", destination: URL(string: \"%@\")!)", encoded];
            sourceOK = source != nil && [source containsString:expected] && ![source containsString:raw];
        }
        NSDictionary *report = @{
            @"source_checked": @(argc == 2),
            @"source_uses_safe_help_url": @(sourceOK),
            @"os": NSProcessInfo.processInfo.operatingSystemVersionString,
            @"raw_url_is_nil": @(original == nil),
            @"encoded_url_is_valid": @(fixed != nil),
            @"components_round_trip": @(componentOK)
        };
        NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:nil];
        puts([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding].UTF8String);
        return fixed != nil && componentOK && sourceOK ? 0 : 1;
    }
}
