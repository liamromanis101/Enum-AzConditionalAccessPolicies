# Enum-AzConditionalAccessPolicies
Enumerates Azure Conditional Access Policies and performs some analysis.

This script gets a count of all users in the tenant for comparision. It then gets each Conditional Access Policy and enumerate all included and excluded users, groups and roles. It then gets the members of each group and users with each role, then it sorts and uniques all included users and members of groups and roles to get a count of all included users accounts. It performs the sam functions on excluded users, groups and roles to get a count of all unique excluded users. Because the script gets a count of all users in the tenant we can calculate the total number of users not affected by a policy [total users - total unique included users]. The  script also gets a list of all included and excluded Apps and Resources. There is some output to the screen and a CSV file is output at the end. 

The output should provide a simple view of the state of conditional access policies in the tenant so that issues can be more easily spotted. 

# To Do
There are currently some issues/errors enumerating some group, resource and app names. This does not affect the analysis however as this is performed using objects.  

