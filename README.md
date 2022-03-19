# HELICON ISAPI

# Redirect XMPie interfaces from Proxy to Application server

This will create a proxy redirection to the application server.
In XMPie HOSTED servers, the Target should be the FQDN (domain or sub-domain)

Parameters:
* Target (FULL domain)
* Includes SSL rules?
* With interfaces to redirect: XMPieDashboard, uStoreAdmin, MarketingConsole	

```
#------------------------------------------------------------#
# redirecting XMPie interfaces to: Target.com                #
#------------------------------------------------------------#

#redirecting XMPieDashboard to Target.com
RewriteCond %{HTTP:Host} (.*)
RewriteCond %{HTTPS} off
RewriteProxy /XMPieDashboard(.*)$ http://Target.com/XMPieDashboard/$1 [NC,U]

#redirecting SSL XMPieDashboard to Target.com
RewriteCond %{HTTP:Host} (.*)
RewriteCond %{HTTPS} on
RewriteProxy /XMPieDashboard(.*)$ https://Target.com/XMPieDashboard/$1 [NC,U]

#redirecting uStoreAdmin to Target.com
RewriteCond %{HTTP:Host} (.*)
RewriteCond %{HTTPS} off
RewriteProxy /uStoreAdmin(.*)$ http://Target.com/uStoreAdmin/$1 [NC,U]

#redirecting SSL uStoreAdmin to Target.com
RewriteCond %{HTTP:Host} (.*)
RewriteCond %{HTTPS} on
RewriteProxy /uStoreAdmin(.*)$ https://Target.com/uStoreAdmin/$1 [NC,U]

#redirecting MarketingConsole to Target.com
RewriteCond %{HTTP:Host} (.*)
RewriteCond %{HTTPS} off
RewriteProxy /MarketingConsole(.*)$ http://Target.com/MarketingConsole/$1 [NC,U]

#redirecting SSL MarketingConsole to Target.com
RewriteCond %{HTTP:Host} (.*)
RewriteCond %{HTTPS} on
RewriteProxy /MarketingConsole(.*)$ http://Target.com/MarketingConsole/$1 [NC,U]
```



# Redirect domain to static URL

This will work only when the user goes to the domain without any additional text.
i.e., it will work in this case: www.domain.com
And it will not work in this case: www.domain.com/path

Parameters: 
* Domain without www
* Target
* Original domain includes SSL?

```
#for domain Domain without any parameter to go to Target
RewriteCond %{HTTPS} off
RewriteCond %{HTTP_HOST} ^(www\.)?Domain$ [NC]
RewriteCond %{REQUEST_URI} !^/(robots\.txt|favicon\.ico|.*\.axd)$ [NC]
RewriteRule ^(/)$ Target [QSA,R=301]
```



# Make sure that Circle friendly URL without an RID will not get 404

Parameters: 
* Friendly URL WITHOUT path
* Path in friendly URL
* Path to fallback page, when there is no RID eg. http://127.0.0.1/{websitefolder}/index.html

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


# Handling uStoreWSAPI in general way

Veracore (Pro-mail) integration if uStore behind firewall

Parameters:
* Domain
* Internal uStore IP address

```
#------------------------------------------------------------#
# Handling uStoreWSAPI in general way                        #
# Veracore (Pro-mail) integration if uStore behind firewall  #
#------------------------------------------------------------#

RewriteCond %{HTTPS} off
RewriteCond %{HTTP_Host} ^DOMAIN$
RewriteRule /uStoreWSAPI/(.*)$ http://uStoreInternalIP/uStoreWSAPI/$1 [NC,U,L,P]

RewriteCond %{HTTPS} on
RewriteCond %{HTTP_Host} (.*)
RewriteRule /uStoreWSAPI/(.*)$ https://%1/uStoreWSAPI/$1 [NC,U,L,P]
```



# Proxy Server Only!!! Permit a particular ip to access ustore admin and/or updates

This is only relevant for proxy configurations.
In a 'Solo' configuration any IP will be able to access the admin interface

Parameters:
* Domain
* uStore internal IP address
* Allowed IP address

```
#-----------------------------------------------------#
# uStore ADMIN: Permit only a particular ip to access #
#-----------------------------------------------------#
# Use this if you want to redirect non-SSL links
RewriteCond %REMOTE_ADDR Allowed IP
RewriteCond %{HTTPS} off
RewriteCond %{HTTP:Host} ^Domain$
RewriteProxy /ustoreadmin(.*)$ http://uStoreInternalIP/ustoreadmin/$1 [NC,U]

# Use this if you want to redirect SSL links
# In case of SSL (https) links, we are redirecting to the same domain name ->
# so make sure that the server with Helicon resolves the domain to the uStore server
RewriteCond %REMOTE_ADDR Allowed IP
RewriteCond %{HTTPS} on
RewriteCond %{HTTP:Host} ^Domain$
RewriteProxy /ustoreadmin(.*)$ https://domain/ustoreadmin/$1 [NC,U]

#-------------------------------------------------------#
# uStore UPDATES: Permit only a particular ip to access #
#-------------------------------------------------------#

# Use this if you want to redirect non-SSL links
RewriteCond %REMOTE_ADDR Allowed IP
RewriteCond %{HTTPS} off
RewriteCond %{HTTP:Host} ^Domain$
RewriteProxy /ustoreupdate(.*)$ http://uStoreInternalIP/ustoreupdate/$1 [NC,U]

# Use this if you want to redirect SSL links
# In case of SSL (https) links, we are redirecting to the same domain name ->
# so make sure that the server with Helicon resolves the domain to the uStore server
RewriteCond %REMOTE_ADDR Allowed IP
RewriteCond %{HTTPS} on
RewriteCond %{HTTP:Host} ^Domain$
RewriteProxy /ustoreupdate(.*)$ https://domain/ustoreupdate/$1 [NC,U]
```



# Add WWW to a specific domain

This is useful when uEdit is in use, since uEdit does not work with sub-domains

Parameter: 
* Domain

```
#----------------------------#
# Add WWW to a domain        #
#----------------------------#

RewriteCond %{HTTPS} (on)?
RewriteCond %{HTTP:Host} ^(Domain)$ [NC]
RewriteCond %{REQUEST_URI} (.+)
RewriteRule .? http(?%1s)://www.%2%3 [R=301,L]
```



# Remove WWW from a specific domain

It is sometimes needed in order to get a PURL to work.

Parameters:
* Domain without www
* Target should always be in SSL?

```
#----------------------------#
# REMOVE WWW from a domain   #
#----------------------------#

RewriteEngine on
RewriteCond %{HTTP_HOST} ^(www.Domain)$
RewriteRule ^(.*)$ http://Domain$1 [R=301,L]
```
