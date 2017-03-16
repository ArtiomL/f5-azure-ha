# Disable functionality that enforces single NIC setup
tmsh modify /sys db provision.1nicautoconfig value disable

# Confirm that the value was set correctly
tmsh list /sys db provision.1nicautoconfig

# Ensure that both BIG-IP VEs are running the same version of system software
tmsh show /sys version

# On each BIG-IP VE, specify the Azure static private IP address as the self IP address for config sync
tmsh modify /cm device <bigipX> configsync-ip <self-ip>

# Establish device trust: On one BIG-IP VE, enter the private IP address of the other BIG-IP VE, along with the username and password
tmsh modify /cm trust-domain add-device { device-ip <peer-ip> device-name <bigipY> username <username> password <password> }

# Create a sync-failover device group with network failover disabled
tmsh create /cm device-group <device-group> devices add { <all-device-names-separated-by-space> } type sync-failover auto-sync enabled network-failover disabled

# Sync one BIG-IP VE to the other
tmsh run /cm config-sync to-group <device-group>
