import pyad.adquery
import re
import csv
import argparse
import sys

parser = argparse.ArgumentParser(description="Get sAMAccountNames from"
                                             " Email Addresses")
parser.add_argument("input", help="Plaintext list of Email addresses")
parser.add_argument("output", help="Output to CSV file")


if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()

# set up variable names for the arguments
ifile = args.input
ofile = args.output

email_addresses = []
samaccountnames = []
display_names = []
result = []
base_dn = "OU=User Accounts, DC=example, DC=com"

in_file = open(ifile, 'r')
out_file = open(ofile, 'wb')
writer = csv.writer(out_file, delimiter = '\n')

for line in in_file:
    if "'" in line:
        line = line.replace("'", "''")
    email_addresses.append(line.strip())

# set up 3 lists for the LDAP queries
for address in email_addresses:
    email = address.split('@')[0]
    samaccountnames.append(email)
    full_name = re.match(r'(.+)\.(.+)@', address)
    if full_name:
        display = '%s, %s' % (full_name.group(2), full_name.group(1))
        display_names.append(display)
in_file.close()

# configure the LDAP query to use local host settings
q = pyad.adquery.ADQuery()

# this will check for valid email addresses in AD
for address in email_addresses:
    try:
        q.execute_query(
            attributes = ["mail", "samaccountname"],
            where_clause = "mail = '%s'" % address,
        )
        for row in q.get_results():
            result.append(row["samaccountname"])
    except:
        print "[-] Email LDAP query failed on %s" % address

# this will check for valid sAMAccountNames before the @
for samaccountname in samaccountnames:
    try:
        q.execute_query(
            attributes = ["samaccountname"],
            where_clause = "samaccountname = '%s'" % samaccountname,
        )
        for row in q.get_results():
            result.append(row["samaccountname"])
    except:
        print "[-] sAMAccountName LDAP query failed on %s" % samaccountname

# this will look for names with a period in it, split the name and
# search for a valid display name ie 'lastname, firstname'
for display_name in display_names:
    try:
        q.execute_query(
            attributes = ["displayname", "samaccountname"],
            where_clause = "displayname = '%s'" % display_name,
        )
        for row in q.get_results():
            result.append(row["samaccountname"])
    except:
        print "[-] Display Name LDAP query failed on %s" % display_name

# remove duplicate entries
result = set(result)
# sort list ignoring case
result = sorted(result, key=lambda s: s.lower())

for samaccountname in result:
    print samaccountname

writer.writerow(result)
out_file.close()
print "\n[+] Wrote %i sAMAccountName(s) to '%s'" % (len(result), ofile)





