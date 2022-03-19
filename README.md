# Redirect XMPie interfaces from Proxy to Application server

This will create a proxy redirection to the application server
## redirecting Interface to Target

```
RewriteCond %{HTTP:Host} (.*)
RewriteCond %{HTTPS} off
RewriteProxy /Interface(.*)$ http://Target/Interface/$1 [NC,U]
```

In XMPie HOSTED servers, the Target should be the FQDN (domain or sub-domain)
Target (FULL domain): mika.com
Includes SSL rules?

Interfaces to redirect:
XMPieDashboard, uStoreAdmin, MarketingConsole	


# Redirect domain to static URL

This will work only when the user goes to the domain without any additional text.

i.e., it will work in this case:
www.domain.com

And it will not work in this case:
www.domain.com/path

```
#for domain Domain without any parameter to go to Target
RewriteCond %{HTTPS} off
RewriteCond %{HTTP_HOST} ^(www\.)?Domain$ [NC]
RewriteCond %{REQUEST_URI} !^/(robots\.txt|favicon\.ico|.*\.axd)$ [NC]
RewriteRule ^(/)$ Target [QSA,R=301]
```
Domain without www	
mika.com
Target	
test.com
Original domain includes SSL?


# Make sure that Circle friendly URL without an RID will not get 404

```
#Rules for FriendlyURL/Path
RewriteCond %{HTTPS} off
RewriteCond %{HTTP_Host} (^(?:www\.)?FriendlyURL$) [NC]
RewriteCond %{REQUEST_URI} !^/(robots\.txt|favicon\.ico|.*\.axd)$ [NC]
RewriteRule ^/Path+$ %{REQUEST_URI}/ [L,R=301]

RewriteCond %{HTTPS} off
RewriteCond %{HTTP_Host} (^(?:www\.)?FriendlyURL$) [NC]
RewriteCond %{REQUEST_URI} !^/(robots\.txt|favicon\.ico|.*\.axd)$ [NC]
RewriteRule ^/Path/$ Fallback [NC,L,P,QSA]
```
