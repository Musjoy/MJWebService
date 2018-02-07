#
# Be sure to run `pod lib lint MJWebService.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = "MJWebService"
  s.version          = "0.1.17"
  s.summary          = "Encapsulation For AFNetworking."

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!


  s.homepage         = "https://github.com/Musjoy/MJWebService"
  # s.screenshots     = "www.example.com/screenshots_1", "www.example.com/screenshots_2"
  s.license          = 'MIT'
  s.author           = { "Raymond" => "Ray.musjoy@gmail.com" }
  s.source           = { :git => "https://github.com/Musjoy/MJWebService.git", :tag => "v-#{s.version}" }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target = '7.0'

  s.source_files = 'MJWebService/Classes/**/*'

  s.user_target_xcconfig = {
    'GCC_PREPROCESSOR_DEFINITIONS' => 'MODULE_WEB_SERVICE'
  }


  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'Foundation'
  s.dependency 'AFNetworking/NSURLSession', '~> 3.1.0'
  s.dependency 'ModuleCapability', '~> 0.1.1'
  s.prefix_header_contents = '#import "ModuleCapability.h"'
end
