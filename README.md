[![Build Status](https://travis-ci.org/augustd/burp-suite-utils.svg?branch=master)](https://travis-ci.org/augustd/burp-suite-utils)

# burp-suite-utils
Utilities for creating Burp Suite Extensions, including the [Burp Extensions API](https://portswigger.net/burp/extender/api/index.html) interfaces. 

View our [AppSec USA 2015 presentaton about this project](http://www.slideshare.net/AugustDetlefsen/appsec-usa-2015-customizing-burp-suite) on SlideShare.

## Building: 
`mvn clean install`

## Usage with Maven: 
Add the following Maven dependency to pom.xml:
```xml
<dependency>
  <groupId>com.codemagi</groupId>
  <artifactId>burp-suite-utils</artifactId>
  <version>1.0.0</version>
</dependency>
```
Add the Maven Shade Plugin to your project's plugins to create a plugin jar that includes all dependencies: 

```xml 
<plugin>
	<groupId>org.apache.maven.plugins</groupId>
	<artifactId>maven-shade-plugin</artifactId>
	<version>2.4.3</version>
	<executions>
		<execution>
			<phase>package</phase>
			<goals>
				<goal>shade</goal>
			</goals>
			<configuration>
				<createDependencyReducedPom>false</createDependencyReducedPom>
			</configuration>
		</execution>
	</executions>
</plugin>
```
