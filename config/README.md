Steps to get started:

Create a 'settings.py' file
Make it executable: chmod 700 settings.py

- [Required] Edit the file and enter your MISP URL:

MISPURL='https://mymisp.mydomain.somewhere'  

- [Required] Choose a MISP token. You can find this by viewing the user whose API token you want to use:

MISPTOKEN='abcdef1234567890...'  

- [Required] Now enter the same config settings for EIQ. First, config the URL (the '/api' part is added automatically):

EIQURL='https://myeiq.localdomain'  

- [Required] Enter the username and password:

EIQUSER='myeiqautomationuser'  
EIQPASS='myeiqautomationpass'  

- [Required] Choose the EIQ 'source' UUID. One username can have multiple sources where it can 'ingest data' from. This 'source' can be
found through the EIQ webinterface and JSON calls.

EIQSOURCE='myeiqautomationsource'  
 
- [Required] Choose a prefix/header that will be added to every EIQ entity for easy searches/recognition

TITLETAG='[MyCERT MISP]'  

- [Optional] Change the SSLVERIFY variable to False if you do not want to verify SSL certificates (e.g. when using self-signed
certificates). Do not disable this unless you are certain and understand the risks.

SSLVERIFY=False  