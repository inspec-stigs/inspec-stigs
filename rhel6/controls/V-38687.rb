# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38687 - The system must provide VPN connectivity for communications over untrusted networks.'

control 'V-38687' do
  impact 0.1
  title 'The system must provide VPN connectivity for communications over untrusted networks.'
  desc '
Providing the ability for remote users or systems to initiate a secure VPN connection protects information when it is transmitted over a wide area network.
'
  tag 'stig','V-38687'
  tag severity: 'low'
  tag checkid: 'C-46249r2_chk'
  tag fixid: 'F-43636r1_fix'
  tag version: 'RHEL-06-000321'
  tag ruleid: 'SV-50488r2_rule'
  tag fixtext: '
The Openswan package provides an implementation of IPsec and IKE, which permits the creation of secure tunnels over untrusted networks. The "openswan" package can be installed with the following command:

# yum install openswan
'
  tag checktext: '
If the system does not communicate over untrusted networks, this is not applicable.

Run the following command to determine if the "openswan" package is installed:

# rpm -q openswan


If the package is not installed, this is a finding.
'

# START_DESCRIBE V-38687
  tag 'untestable'
  # no good way to test if it should comm over untrusted networks
# END_DESCRIBE V-38687

end
