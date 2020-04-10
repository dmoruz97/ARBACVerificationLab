# ARBACVerificationLab

Davide Moruzzi 861645

A simple ARBAC analyser for small policies to solve the role-reachability problem.
In particular, it returns 1 if exists a pair in the user-to-role assignments which contains the target role eventually, 0 otherwise.

## The code

The `main` starts calling the function `parse_arbac_file` which reads the file specified as argument in the command line when the program is being executed.  
The parsing function parses the file and generates different sets which represent an ARBAC policy, i.e. `roles` set, `users` set, `ua` set, `cr` set and `ca` set.  
Then, the main calls the `role_reachability`function passing as arguments all the sets generated before and the target role.  
Initially, the role reachability function calls the `forward_slicing` function which simplifies the instance of the ARBAC policies by removing users and roles with a pruning algorithm (forward slicing).  
Then the `role_reachability_rec` function is called passing as argument, in addition to all the sets seen before, a `user_to_role_explored` set which will contains all the user-to-role assignments already explored.

The idea is to use recursion in such a way to be sure that all the possible combinations of "CAN-ASSIGN" and "CAN-REMOVE" rules will be applied to the ARBAC policy (reasoning by building a tree of all the possibile combinations was useful):  
  - Base case: if the target role is mentioned in the user-to-role assignments it means that it is reachable so return 1. 
  - Inductive step:  
      - for each "can-assign" rule, try to apply it to the instance of the policy. Then call the recursive function by passing a reduced set of CA (the rule just applied is removed). 
       - for each "can-remove" rule, try to apply it to the instance of the policy. Then call the recursive function by passing a reduced set of CR (the rule just applied is removed). 
  - if the funtion never returns 1, eventually returns 0
  
The flag was obtained by executing several time the program, also by applying small changes in the code (in the uploaded code  there are some comments which are the previous version of the program).  
Also a little bit of luck helped.

The code works well with some policies (like 1, 3, 4), with others does not terminate soon.
A problem which I encountered was that the length of the user-to-role assignments set become 0, so the recursive calls never terminate.

## Execution
Run with: `python arbac.py policies/policyX.arbac` where X is between 1 and 8.
