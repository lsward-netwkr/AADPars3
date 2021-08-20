## AADPars3 - Load and commit AzureAD Sign-In data to database.
## a Lee Ward (l.ward@netwkr.net) tool, developed September 2018.
## Started development 20/08/2021 at v0.1

## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU Affero General Public License.

## More information about your rights under the AGPL 3.0
## Please see: https://www.gnu.org/licenses/agpl-3.0.en.html

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

## Note: I'm not a developer, I'm an IT Security Officer in my day job and an IT engineer at all other times.
## Code quality wasn't what I was going for when I made this, I just needed a quick solution so I could
## quickly browse Azure AD data for threat hunting purposes.
## I'm inexperienced in Python, so please forgive the mess!

## Requires:
## Python 3.9 (tested on Windows)
## MySQL connector for Python (installed with the MySQL Installer or via pip install mysql.connector)
## A MySQL server, either local or remote. I've tested this with a local MySQL 8.0 server, with the password stored as legacy/native mysql.

## import dependencies. ensure that you've pip installed mysql.connector. 
import os
import time
import mysql.connector
from mysql.connector import errorcode
import csv

print("AADPars3 v0.1 (20/08/2021) licenced under GPLv3")
print("=============------")
print("A quickly hacked-together at-home tool by Lee Ward (l.ward@netwkr.net)")
print("\n")
print("AADPars3 Copyright (c)2021 Lee Ward")
print("This program comes with ABSOLUTELY NO WARRANTY.")
print("For information, please visit gnu.org/licenses/agpl-3.0.en.html")
print("This is free software, and you are welcome to redistribute it")
print("under certain conditions under the AGPL v3.")
print("\n")
print("------======= TASK BEGIN =======------")
print("\n")

## Connect to MySQL/MariaDB...
## IMPORTANT: Edit DB credentials as required.
## ALSO IMPORTANT: The table this works with has the following CREATE statement:
''' BEGIN...
CREATE TABLE data (
`Date` varchar(50) NOT NULL,
`RequestID` varchar(50) NOT NULL,
`CorrelationID` varchar(50) NOT NULL,
`UserID` varchar(50) NOT NULL,
`User` varchar(50) NOT NULL,
`Username` varchar(50) NOT NULL,
`UserType` varchar(50) NOT NULL,
`CrossTenantAccessType` varchar(50) NOT NULL,
`Application` varchar(50) NOT NULL,
`ApplicationID` varchar(50) NOT NULL,
`Resource` varchar(50) NOT NULL,
`ResourceID` varchar(50) NOT NULL,
`ResourceTenantID` varchar(50) NOT NULL,
`HomeTenantID` varchar(50) NOT NULL,
`IPAddress` varchar(50) NOT NULL,
`Location` varchar(50) NOT NULL,
`Status` varchar(50) NOT NULL,
`SignInErrorCode` varchar(50) NOT NULL,
`FailureReason` varchar(50) NOT NULL,
`ClientApp` varchar(50) NOT NULL,
`DeviceID` varchar(50) NOT NULL,
`Browser` varchar(50) NOT NULL,
`OperatingSystem` varchar(50) NOT NULL,
`Compliant` varchar(50) NOT NULL,
`Managed` varchar(50) NOT NULL,
`JoinType` varchar(50) NOT NULL,
`MFAResult` varchar(50) NOT NULL,
`MFAAuthMethod` varchar(50) NOT NULL,
`MFAAuthDetail` varchar(50) NOT NULL,
`AuthenticationRequirement` varchar(50) NOT NULL,
`SignInIdentifier` varchar(50) NOT NULL,
`IPAddressResource` varchar(50) NOT NULL,
`ASN` varchar(50) NOT NULL,
`FlaggedForReview` varchar(50) NOT NULL,
`TokenIssuerType` varchar(50) NOT NULL,
`TokenIssuerName` varchar(50) NOT NULL,
`Latency` varchar(50) NOT NULL,
`ConditionalAccess` varchar(50) NOT NULL,
PRIMARY KEY (`ResourceID`)) ENGINE=InnoDB AUTO_INCREMENT=1379 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
...END '''

try:
    dbc = mysql.connector.connect(user='EnterUsernameHere', password='EnterPasswordHere', host='DBHostHere', database='aadpars3')

except mysql.connector.Error as err:
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("!! Credential Error - Database connection fail. Errors may persist...")
    elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("!! Database Error - Database doesn't exist? Errors may persist...")
    else:
        print(err)
else:
    print(">> DB connection good.")

cursor = dbc.cursor(buffered=True)
## Hack so I can see how many new items got added (if any). Should implement this with a bit more finesse when more experienced.
num = 1

## open csv data file
with open('data.csv') as csvfile:
    data = csv.reader(csvfile, delimiter=',')
    ## Skip headers
    next(data)
    for row in data:
        ## Check if record exists
        query = "SELECT * FROM data WHERE RequestID = %s"
        cursor.execute(query, (row[1],))
        if cursor.rowcount > 0:
            ## Skip
            print(">> Request ID already exists, skipping...")
                        
        else:
            ## Add new record.
            query = "INSERT INTO data (Date,RequestID,CorrelationID,UserID,User,Username,UserType,CrossTenantAccessType,Application,ApplicationID,Resource,ResourceID,ResourceTenantID,HomeTenantID,IPAddress,Location,Status,SignInErrorCode,FailureReason,ClientApp,DeviceID,Browser,OperatingSystem,Compliant,Managed,JoinType,MFAResult,MFAAuthMethod,MFAAuthDetail,AuthenticationRequirement,SignInIdentifier,IPAddressResource,ASN,FlaggedForReview,TokenIssuerType,TokenIssuerName,Latency,ConditionalAccess) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            qdata = (row[0],row[1],row[2],row[3],row[4],row[5],row[6],row[7],row[8],row[9],row[10],row[11],row[12],row[13],row[14],row[15],row[16],row[17],row[18],row[19],row[20],row[21],row[22],row[23],row[24],row[25],row[26],row[27],row[28],row[29],row[30],row[31],row[32],row[33],row[34],row[35],row[36],row[37])
            cursor.execute(query, (qdata))
            print(">> New record",num,"for Request ID",row[1],"ready for commit...")
            num = num+1

## DB commits aren't automatically performed, until we...
dbc.commit()
print(">> Data committed successfully!")

## Close MySQL/MariaDB connection
print(">> Closing DB connection...")
dbc.close()

print(">> Complete. Data is ready for use.")
print("------======= TASK END =======------")