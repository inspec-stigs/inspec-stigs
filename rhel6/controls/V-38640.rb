# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38640 - The Automatic Bug Reporting Tool (abrtd) service must not be running.'

control 'V-38640' do
  impact 0.1
  title 'The Automatic Bug Reporting Tool (abrtd) service must not be running.'
  desc '
Mishandling crash data could expose sensitive information about vulnerabilities in software executing on the local machine, as well as sensitive information from within a process\'s address space or registers.
'
  tag 'stig','V-38640'
  tag severity: 'low'
  tag checkid: 'C-46200r1_chk'
  tag fixid: 'F-43589r2_fix'
  tag version: 'RHEL-06-000261'
  tag ruleid: 'SV-50441r2_rule'
  tag fixtext: '
The Automatic Bug Reporting Tool ("abrtd") daemon collects and reports crash data when an application crash is detected. Using a variety of plugins, abrtd can email crash reports to system administrators, log crash reports to files, or forward crash reports to a centralized issue tracking system such as RHTSupport. The "abrtd" service can be disabled with the following commands: 

# chkconfig abrtd off
# service abrtd stop
'
  tag checktext: '
To check that the "abrtd" service is disabled in system boot configuration, run the following command: 

# chkconfig "abrtd" --list

Output should indicate the "abrtd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "abrtd" --list
"abrtd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "abrtd" is disabled through current runtime configuration: 

# service abrtd status

If the service is disabled the command will return the following output: 

abrtd is stopped


If the service is running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
