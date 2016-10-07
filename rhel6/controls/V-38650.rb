# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38650 - The rdisc service must not be running.'

control 'V-38650' do
  impact 0.1
  title 'The rdisc service must not be running.'
  desc '
General-purpose systems typically have their network and routing information configured statically by a system administrator. Workstations or some special-purpose systems often use DHCP (instead of IRDP) to retrieve dynamic network configuration information.
'
  tag 'stig','V-38650'
  tag severity: 'low'
  tag checkid: 'C-46210r1_chk'
  tag fixid: 'F-43599r2_fix'
  tag version: 'RHEL-06-000268'
  tag ruleid: 'SV-50451r2_rule'
  tag fixtext: '
The "rdisc" service implements the client side of the ICMP Internet Router Discovery Protocol (IRDP), which allows discovery of routers on the local subnet. If a router is discovered then the local routing table is updated with a corresponding default route. By default this daemon is disabled. The "rdisc" service can be disabled with the following commands: 

# chkconfig rdisc off
# service rdisc stop
'
  tag checktext: '
To check that the "rdisc" service is disabled in system boot configuration, run the following command: 

# chkconfig "rdisc" --list

Output should indicate the "rdisc" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "rdisc" --list
"rdisc" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "rdisc" is disabled through current runtime configuration: 

# service rdisc status

If the service is disabled the command will return the following output: 

rdisc is stopped


If the service is running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
