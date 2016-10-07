# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38487 - The system package management tool must cryptographically verify the authenticity of all software packages during installation.'

control 'V-38487' do
  impact 0.1
  title 'The system package management tool must cryptographically verify the authenticity of all software packages during installation.'
  desc '
Ensuring all packages\' cryptographic signatures are valid prior to installation ensures the provenance of the software and protects against malicious tampering.
'
  tag 'stig','V-38487'
  tag severity: 'low'
  tag checkid: 'C-46043r1_chk'
  tag fixid: 'F-43433r1_fix'
  tag version: 'RHEL-06-000015'
  tag ruleid: 'SV-50288r1_rule'
  tag fixtext: '
To ensure signature checking is not disabled for any repos, remove any lines from files in "/etc/yum.repos.d" of the form: 

gpgcheck=0
'
  tag checktext: '
To determine whether "yum" has been configured to disable "gpgcheck" for any repos, inspect all files in "/etc/yum.repos.d" and ensure the following does not appear in any sections: 

gpgcheck=0

A value of "0" indicates that "gpgcheck" has been disabled for that repo. 
If GPG checking is disabled, this is a finding.

If the "yum" system package management tool is not used to update the system, verify with the SA that installed packages are cryptographically signed.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
