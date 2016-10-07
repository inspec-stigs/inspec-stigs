# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38665 - The system package management tool must verify group-ownership on all files and directories associated with the audit package.'

control 'V-38665' do
  impact 0.5
  title 'The system package management tool must verify group-ownership on all files and directories associated with the audit package.'
  desc '
Group-ownership of audit binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The group-ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.
'
  tag 'stig','V-38665'
  tag severity: 'medium'
  tag checkid: 'C-46225r1_chk'
  tag fixid: 'F-43614r1_fix'
  tag version: 'RHEL-06-000280'
  tag ruleid: 'SV-50466r1_rule'
  tag fixtext: '
The RPM package management system can restore file group-ownership of the audit package files and directories. The following command will update audit files with group-ownership different from what is expected by the RPM database: 

# rpm --setugids audit
'
  tag checktext: '
The following command will list which audit files on the system have group-ownership different from what is expected by the RPM database: 

# rpm -V audit | grep \'^......G\'


If there is output, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
