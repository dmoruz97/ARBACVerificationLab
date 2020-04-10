import sys
import datetime

################################################################################
########################### PARSING FUNCTION ###################################
################################################################################
# Function that parses the ARBAC file and returns all the sets contained in it
def parse_arbac_file(arbac_file):
    roles = set()
    users = set()
    ua = set()
    cr = set()
    ca = set()
    goal = ""

    file = open(arbac_file, 'r')
    lines = file.readlines()

    for line in lines:
        split_line = line.split(" ")
        if (split_line[0] == "Roles"):
            roles.update(split_line[1:len(split_line)-1])
        elif (split_line[0] == "Users"):
            users.update(split_line[1:len(split_line)-1])
        elif (split_line[0] == "UA"):
            ua.update(split_line[1:len(split_line)-1])
        elif (split_line[0] == "CR"):
            cr.update(split_line[1:len(split_line)-1])
        elif (split_line[0] == "CA"):
            ca.update(split_line[1:len(split_line)-1])
        elif (split_line[0] == "Goal"):
            goal = split_line[1:len(split_line)-1][0]
    file.close()

    return roles, users, ua, cr, ca, goal

################################################################################
######################## FORWARD SLICING FUNCTION ##############################
################################################################################
# Function that performs forward_slicing to reduce the complexity of Users and Roles sets
def forward_slicing(roles, users, ua, cr, ca):

    # initialize set_0
    set_0 = set()
    for r in roles:
        for u in users:
            pair = "<{},{}>".format(u,r)
            if pair in ua:
                set_0.add(r)

    # compute set_i
    empty_set = set()
    set_i = set()
    i = 0;
    while (set_0.difference(set_i) != empty_set):  # while not reached the fix point
        if (i > 0):
            set_0.clear()   # set_0 is equal to set_i-1
            set_0 = set_i.copy();
        set_i = set_0.union(create_subset(ca, set_0))
        i = i+1

    print("\nFIX POINT FOUND!")
    r_minus_set_i = roles.difference(set_i)

    # Remove from CA all the rules that include any role in R\S* in the positive
    # preconditions or in the target
    new_ca = ca.copy()
    for r in ca:
        split_r = r[1:len(r)-1].split(',')
        for role in r_minus_set_i:
            substr = split_r[1].find(role)  # in preconditions

            # Create set of positive preconditions
            pos_conditions = set()
            cond_split = split_r[1].split('&')
            for c in cond_split:
                if (c[0] != '-'):
                    pos_conditions.add(c[1:])

            substr2 = split_r[2].find(role) # in target

            if (substr!=-1 or substr2!=-1):   # occurrency found
                if (substr==-1 and substr2!=-1):    # ... in target
                    new_ca.remove(r)
                elif (substr!=-1 and substr2==-1):   # ... in preconditions
                    if pos_conditions!=set() and pos_conditions.issuperset(set(role))==True:
                        new_ca.remove(r)

    ca.clear()
    ca = new_ca.copy()

    # Remove from CR all the rules that mention any role in R\S*
    new_cr = cr.copy()
    for r in cr:
        #if (r != ""):
        split_r = r[1:len(r)-1].split(',')
        for role in r_minus_set_i:
            if (split_r[0]==role or split_r[1]==role):   # occurrency found
                new_cr.remove(r)

    cr.clear()
    cr = new_cr.copy()

    # Remove the roles R\S* from the negative preconditions of all rules
    new_ca = ca.copy()
    for r in ca:
        split_r = r[1:len(r)-1].split(',')
        for role in r_minus_set_i:
            substr = split_r[1].find(role)
            if (substr != -1 and split_r[1][substr-1] == '-'):   # occorrenza trovata
                if (split_r[1][substr-2] == '&'):
                    new_ca.remove(r)
                    split_r.replace("&-{}".format(role), "")
                    new_ca.add()
                elif (split_r[1][substr+len(role)] == '&'):
                    new_ca.remove(r)
                    split_r.replace("-{}&".format(role), "")
                    new_ca.add()
                else:
                    new_ca.remove(r)
                    split_r.replace("-{}".format(role), "") # or with TRUE instead ""
                    new_ca.add()
    ca.clear()
    ca = new_ca.copy()

    # Delete the roles R\S*
    new_roles = roles.copy()
    for r in roles:
        for role in r_minus_set_i:
            if (r == role):
                new_roles.remove(r)
    roles.clear()
    roles = new_roles.copy()

    # Delete user-role since some roles were removed
    new_ua = ua.copy()
    for u_r in ua:
        split_u_r = u_r[1:len(u_r)-1].split(',')
        for role in r_minus_set_i:
            if (split_u_r[1] == role):
                new_ua.remove(u_r)

    ua.clear()
    ua = new_ua.copy()

    return roles, ua, cr, ca

###############################################
def create_subset(ca, set_0):
    role_out = set()

    for t in ca:
        temp = t[1:len(t)-1].split(',')
        r_a = temp[0]
        R_p = temp[1]
        R_n = temp[1]
        r_t = temp[2]

        # Pre-condition
        if (R_p != "TRUE"):
            rp = R_p.split('&')
            R_p = set()
            for x in rp:
                if (x[0] != '-'):
                    R_p.add(x)
        else:
            R_p = set()

        temp_set = R_p.union({r_a})
        if (set_0.issuperset(temp_set)):
            role_out.add(r_t)

    return role_out


################################################################################
######################### AUXILIARY FUNCTIONS ##################################
################################################################################
def get_roles_from_ua_given_user(ua, user):
    roles = set()

    for u_r in ua:
        split_u_r = u_r[1:len(u_r)-1].split(',')
        if (split_u_r[0] == user):
            roles.add(split_u_r[1])

    return roles


def get_users_from_ua_given_role(ua, role):
    users = set()

    for u_r in ua:
        split_u_r = u_r[1:len(u_r)-1].split(',')
        if (split_u_r[1] == role):
            users.add(split_u_r[0])

    return users


def get_users_from_ua_respecting_conditions(ua, ca):
    users = set()
    pos_conditions = set()
    neg_conditions = set()

    split_c_a = ca[1:len(ca)-1].split(',')
    admin_role = split_c_a[0]
    condition = split_c_a[1]

    if (condition == "TRUE"):   # Select all users who have administrative role as in UA
        for u_r in ua:
            split_u_r = u_r[1:len(u_r)-1].split(',')
            if (split_u_r[1] == admin_role):
                users.add(split_u_r[0])
    else:
        cond_split = condition.split('&')
        for c in cond_split:
            if (c[0] == '-'):
                neg_conditions.add(c[1:])
            else:
                pos_conditions.add(c)

        for u_r in ua:
            split_u_r = u_r[1:len(u_r)-1].split(',')
            user1 = split_u_r[0] # Get user and compare it with all other users

            satisfy = 1
            for u_r2 in ua:
                if u_r != u_r2:
                    split_u_r2 = u_r2[1:len(u_r2)-1].split(',')
                    user2 = split_u_r2[0]
                    if (user1 == user2):
                        # satisfy all preconditions and negative conditions
                        temp_set = set()
                        temp_set.add(split_u_r2[1])
                        if temp_set.issubset(neg_conditions)==True or temp_set.issubset(pos_conditions)==False:
                            satisfy = 0
            if satisfy==1:
                users.add(user1)

    return users

##################################################
def apply_CR_rule_to_UA(cr_rule, ua):
    split_c_r = cr_rule[1:len(cr_rule)-1].split(',')

    users = get_users_from_ua_given_role(ua, split_c_r[0])
    if (len(users) >= 1):    # if exist some users with the administrative role in ua...
        temp_ua = ua.copy()
        for u_a in ua:
            split_u_a = u_a[1:len(u_a)-1].split(',')
            if (split_u_a[1] == split_c_r[1]):  # if exists a role that can be removed...
                temp_ua.remove(u_a)
                #break # to remove the first found

        ua.clear()
        ua = temp_ua.copy()

    return ua

##################################################
def apply_CA_rule_to_UA(ca_rule, ua, user_to_role_explored):
    split_c_a = ca_rule[1:len(ca_rule)-1].split(',')

    users = get_users_from_ua_given_role(ua, split_c_a[0])
    if (len(users) >= 1):    # if exist some users with the administrative role in ua...

        # Search for users who respect the conditions in CA rules
        users2 = get_users_from_ua_respecting_conditions(ua, ca_rule)
        if (len(users2) >= 1):    # if exist some users who respect the conditions in ca rules
            for u in users2:
                new_u_r = "<{},{}>".format(u, split_c_a[2])
                temp_set = set(new_u_r)
                if (temp_set.issubset(user_to_role_explored) == False):  # check that the new UA is not in user_to_role_explored set
                    user_to_role_explored.add(new_u_r)
                    ua.add(new_u_r)
                #break # to remove the first found

    return ua, user_to_role_explored

################################################################################
###################### ROLE REACHABILITY FUNCTION ##############################
################################################################################
# Function that solves the role reachability problem given the sets parsed before
def role_reachability(roles, users, ua, cr, ca, goal):

    user_to_role_explored = ua.copy()    # set of user-to-role assignments already explored
    # user_to_role_explored = set()

    roles, ua, cr, ca = forward_slicing(roles, users, ua, cr, ca)  # perform forward_slicing

    # NOT USED
    start_time = datetime.datetime.now()    # initial start time
    timeout_time = start_time + datetime.timedelta(hours=0, minutes=20) # timeout to force termination

    # START COMPUTATION
    #reachable = 0
    reachable = role_reachability_rec(ua, cr, ca, goal, user_to_role_explored)
    #reachable = role_reachability_rec(ua, cr, ca, goal, user_to_role_explored, ca, cr, set(), set())

    return reachable


#def role_reachability_rec(ua, cr, ca, goal, user_to_role_explored, ca_sane, cr_sane, ca_removed, cr_removed):
def role_reachability_rec(ua, cr, ca, goal, user_to_role_explored):

    # len(ua) va a 0 dopo alcune ricorsioni!!!

    # BASE CASE #
    # If target is present in ua assignments -> end of recursion
    for u_r in user_to_role_explored:
        split_u_r = u_r[1:len(u_r)-1].split(',')
        if (split_u_r[1] == goal):
            return 1

    # INDUCTIVE STEP #

    # For all CA
    for c_a in ca:
        ua, user_to_role_explored = apply_CA_rule_to_UA(c_a, ua, user_to_role_explored)
        ca_reduced = ca.copy()
        ca_reduced.remove(c_a)

        """if (ca_removed != set()):
            ca.union(ca_removed)
        ca_removed = set(c_a)"""

        role_reachability_rec(ua, cr, ca_reduced, goal, user_to_role_explored)
        #role_reachability_rec(ua, cr_sane, ca_reduced, goal, user_to_role_explored, ca_sane, cr_sane, ca_removed, cr_removed)
        #role_reachability_rec(ua, cr, ca, goal, user_to_role_explored)

    # For all CR
    for c_r in cr:
        ua = apply_CR_rule_to_UA(c_r, ua)
        cr_reduced = cr.copy()
        cr_reduced.remove(c_r)

        """if (cr_removed != set()):
            cr.union(cr_removed)
        cr_removed = set(c_r)"""

        role_reachability_rec(ua, cr_reduced, ca, goal, user_to_role_explored)
        #role_reachability_rec(ua, cr_reduced, ca_sane, goal, user_to_role_explored, ca_sane, cr_sane, ca_removed, cr_removed)
        #role_reachability_rec(ua, cr, ca, goal, user_to_role_explored)

    return 0


################################################################################
######################### MAIN FUNCTION ########################################
################################################################################
def main(argv): # in argv is contained the file with ARBAC policies
    print("\nARBAC file: \"{}\"".format(argv[0]))

    # parse the ARBAC file
    roles, users, ua, cr, ca, goal = parse_arbac_file(argv[0])

    # solve the role reachability problem
    result = role_reachability(roles, users, ua, cr, ca, goal)

    print("\nRole reachability result: {}\n".format(result))

if __name__ == "__main__":
   main(sys.argv[1:])
