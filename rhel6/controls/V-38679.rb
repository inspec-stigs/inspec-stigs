# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38679 - The DHCP client must be disabled if not needed.'

control 'V-38679' do
  impact 0.5
  title 'The DHCP client must be disabled if not needed.'
  desc '
DHCP relies on trusting the local network. If the local network is not trusted, then it should not be used. However, the automatic configuration provided by DHCP is commonly used and the alternative, manual configuration, presents an unacceptable burden in many circumstances.
'
  tag 'stig','V-38679'
  tag severity: 'medium'
  tag checkid: 'C-46242r2_chk'
  tag fixid: 'F-43628r2_fix'
  tag version: 'RHEL-06-000292'
  tag ruleid: 'SV-50480r2_rule'
  tag fixtext: '
For each interface [IFACE] on the system (e.g. eth0), edit "/etc/sysconfig/network-scripts/ifcfg-[IFACE]" and make the following changes.

Correct the BOOTPROTO line to read:

BOOTPROTO=none


Add or correct the following lines, substituting the appropriate values based on your site\'s addressing scheme:

NETMASK=[local LAN netmask]
IPADDR=[assigned IP address]
GATEWAY=[local LAN default gateway]
'
  tag checktext: '
To verify that DHCP is not being used, examine the following file for each interface.

# /etc/sysconfig/network-scripts/ifcfg-[IFACE]

If there is any network interface without a associated "ifcfg" file, this is a finding.

Look for the following:

BOOTPROTO=none

Also verify the following, substituting the appropriate values based on your site\'s addressing scheme:

NETMASK=[local LAN netmask]
IPADDR=[assigned IP address]
GATEWAY=[local LAN default gateway]


If it does not, this is a finding.
'

# START_DESCRIBE V-38679
  tag 'dhcp','untestable'
  # no good way to check for "if not needed" especially
  # as a lot of cloud resources use dhcp
# END_DESCRIBE V-38679

end
