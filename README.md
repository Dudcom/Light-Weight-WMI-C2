# Light-Weight-WMI-C2
WMI Tool Created for Post Exploitation Enviorments to create a chained Persistence allowing for attackers to maintain connection to device regardless of defenesive tactics 


# Useage:
Start by seeding the powershell file through the seed.txt file, this will define the attack surface for the tool. 

The tool will then apply polices to the boxes being attacked, and then push the folder pushsys into C:\pushsys which can be then used to stage scripts/malware as needed on the boxes 
afterwords you get a shell which is able to send commands over WMI to all boxes, to exist the shell just hit enter with no information filled out. 
