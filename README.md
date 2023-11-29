# fmc-logging-audit
create report on access control policy logging settings per best practices


This script will generate a csv file dump of an access control policy logging settings
In keeping with best practices, deny rules shouls log at the begining of the flow
and allow rules should log at the end of the flow.  the output of this script will
aid in a quick audit of the logging settings per the best practice


 global variable BASE_URL will need to be updated with the url/IP of your FMC

 - Developed and tested with the following environment
 - OS: windows10
 - Python: 3.11.5
 - Target platform:  FMC 7.0.4
 - Limitations: function getRules uses a limit of 1000. if your ACP contains more than 1000 rules
               the function will need to be adapted for paging
