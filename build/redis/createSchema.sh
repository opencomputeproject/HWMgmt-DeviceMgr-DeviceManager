redis-cli -p 6380 <<HERE
Set  "registry:assignedprivileges"  '{"List":["Login", "ConfigureManager", "ConfigureUsers", "ConfigureSelf", "ConfigureComponents"]}'
Set "roles:redfishdefined"  '{"List":["Administrator", "Operator", "ReadOnly"]}'
Set "User:admin"  '{"UserName":"admin","Password":"O01bKrP7Tzs7YoO3YvQt4pRa2J_R6HI34ZfP4MxbqNIYAVQVt2ewGXmhjvBfzMifM7bHFccXKGmdHvj3hY44Hw==","RoleId":"Administrator", "AccountTypes":["Redfish"]}'
Set "role:Administrator"  '{"@odata.type":"","RoleId":"Administrator","Name":"","Description":"","IsPredefined":true,"AssignedPrivileges":["ConfigureSelf","Login","ConfigureUsers","ConfigureComponents","ConfigureManager"],"OemPrivileges":null,"@odata.context":"","@odata.id":""}'
Set "role:Operator"  '{"@odata.type":"","RoleId":"Operator","Name":"","Description":"","IsPredefined":true,"AssignedPrivileges":["ConfigureSelf","Login","ConfigureComponents"],"OemPrivileges":null,"@odata.context":"","@odata.id":""}'
Set "role:ReadOnly"  '{"@odata.type":"","RoleId":"ReadOnly","Name":"","Description":"","IsPredefined":true,"AssignedPrivileges":["ConfigureSelf","Login"],"OemPrivileges":null,"@odata.context":"","@odata.id":""}'
keys *
SAVE
HERE
