Steps to get started:

1) [Required] Create a 'settings.py' file  
2) [Required] Make it executable: chmod 700 settings.py  
3) [Required] Edit the file and enter your MISP URL:

MISPURL='https://mymisp.mydomain.somewhere'  
 
4) [Required] Choose a MISP token. You can find this by viewing the user whose API token you want to use:
 
MISPTOKEN='abcdef1234567890...'  
  
5) [Required] Now enter the same config settings for EIQ. First, pick the right URL: 'https://myeiq.localdomain'. Secondly, pick '/api' as the EIQVERSION for EIQ <=2.0.x, and '/private' for EIQ 2.1.x+  

EIQHOST='https://myeiq.localdomain'  
EIQVERSION='/private'  

6) [Required] Enter the username and password:

EIQUSER='myeiqautomationuser'  
EIQPASS='myeiqautomationpass'  

7) [Required] Choose the EIQ 'source' UUID. One username can have multiple sources where it can 'ingest data' from. This 'source' can be found through the EIQ webinterface and JSON calls.

EIQSOURCE='myeiqautomationsource'  
 
8) [Required] Choose a prefix/header that will be added to every EIQ entity for easy searches/recognition, and choose the maximum title length of attributes types that describe the content of indicators

TITLETAG='[MyCERT MISP]'  
TITLELENGTH=70

9) [Optional] Change the MISPSSLVERIFY and EIQSSLVERIFY variables to False if you do not want to verify SSL certificates (e.g. when using self-signed certificates). Do not disable this unless you are certain and understand the risks.

MISPSSLVERIFY=True  
EIQSSLVERIFY=True  
