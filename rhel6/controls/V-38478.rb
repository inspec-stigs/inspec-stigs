# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38478 - The Red Hat Network Service (rhnsd) service must not be running, unless using RHN or an RHN Satellite.'

control 'V-38478' do
  impact 0.1
  title 'The Red Hat Network Service (rhnsd) service must not be running, unless using RHN or an RHN Satellite.'
  desc '
Although systems management and patching is extremely important to system security, management by a system outside the enterprise enclave is not desirable for some environments. However, if the system is being managed by RHN or RHN Satellite Server the "rhnsd" daemon can remain on.
'
  tag 'stig','V-38478'
  tag severity: 'low'
  tag checkid: 'C-46033r2_chk'
  tag fixid: 'F-43423r2_fix'
  tag version: 'RHEL-06-000009'
  tag ruleid: 'SV-50278r2_rule'
  tag fixtext: '
The Red Hat Network service automatically queries Red Hat Network servers to determine whether there are any actions that should be executed, such as package updates. This only occurs if the system was registered to an RHN server or satellite and managed as such. The "rhnsd" service can be disabled with the following commands: 

# chkconfig rhnsd off
# service rhnsd stop
'
  tag checktext: '
If the system uses RHN or an RHN Satellite, this is not applicable.

To check that the "rhnsd" service is disabled in system boot configuration, run the following command: 

# chkconfig "rhnsd" --list

Output should indicate the "rhnsd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "rhnsd" --list
"rhnsd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "rhnsd" is disabled through current runtime configuration: 

# service rhnsd status

If the service is disabled the command will return the following output: 

rhnsd is stopped


If the service is running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
