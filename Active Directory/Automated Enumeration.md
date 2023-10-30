# Check 
- [ ] Find Workstations where Domain Users can RDP  
- [ ] Find Servers where DomainUsers can RDP  
- [ ] Find Computers where DomainUsers are Local Admin  
- [ ] Shortest Path to Domain Admins from Owned Principals
- [ ] List all kerberoastable accounts

```
Import-Module .\Sharphound.ps1

Invoke-BloodHound -CollectionMethod All -OutputDirectory outputpath -OutputPrefix "anyname"
   
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit" -ZipFilename corpaudit.zip

File Transfer to kali
   
sudo neo4j start 
bloodhound
```

## Raw Query
```
MATCH (m:Computer) RETURN m (list all computer objects)
MATCH (m:User) RETURN m
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p (List all Active User Sessions)
```
Find all unconstrained delegations excluding domain controllers
```
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(c1.name) AS domainControllers MATCH (c2 {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers RETURN c2
```
Find constrained delegation
```
MATCH p=(u:User)-[:AllowedToDelegate]->(c:Computer) RETURN p
```
Find users that can be AS-REP roasted
```
MATCH(u:User {dontreqpreauth: true}) RETURN u
```
Find users with blank passwords that are enabled
```
MATCH (u:User) WHERE NOT u.userpassword IS null AND u.enabled = TRUE RETURN u.name,u.userpassword
```
Find users having password in their description
```
MATCH (m:User) WHERE m.description CONTAINS 'password' RETURN m.name,m.description
```
Find domain users with interesting permissions against GPOs
```
MATCH p=(u:User)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1..]->(g:GPO) RETURN p
```
Find groups that can reset passwords
```
MATCH p=(m:Group)-[r:ForceChangePassword]->(n:User) RETURN p
```
Find groups having local Admin privilege
```
MATCH p=(m:Group)-[r:AdminTo]->(n:Computer) RETURN p
```
Find all users that have local admin rights
```
MATCH p=(m:User)-[r:AdminTo]->(n:Computer) RETURN p
```
Find all active Domain Admin sessions
```
MATCH (n:User)-[:MemberOf]->(g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = (c:Computer)-[:HasSession]->(n) return p
```
Find all Certificates templates
```
MATCH (n:GPO) WHERE n.type = 'Certificate Template' RETURN n
```
Find enabled certificates templates
```
MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.Enabled = true RETURN n
```
Find ESC1 Misconfigured Certificate Templates
```
MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enrollee Supplies Subject` = true and n.`Client Authentication` = true and n.`Enabled` = true RETURN n
```
Find ESC2 Misconfigured Certificate Template
```
MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' INn.`Extended Key Usage`) RETURN n
```
Find Certificate Authorities with HTTP verb enrollment (ECS8)
```
MATCH (n:GPO) WHERE n.type = 'Enrollment Service' and n.`Web Enrollment` = 'Enabled' RETURN n
```

## Reference 
Very Useful for exploiting Rights or others using BloodHound Info - https://burmat.gitbook.io/security/hacking/domain-exploitation