# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38677 - The NFS server must not have the insecure file locking option enabled.'

control 'V-38677' do
  impact 1.0
  title 'The NFS server must not have the insecure file locking option enabled.'
  desc '
Allowing insecure file locking could allow for sensitive data to be viewed or edited by an unauthorized user.
'
  tag 'stig','V-38677'
  tag severity: 'high'
  tag checkid: 'C-46239r1_chk'
  tag fixid: 'F-43626r1_fix'
  tag version: 'RHEL-06-000309'
  tag ruleid: 'SV-50478r1_rule'
  tag fixtext: '
By default the NFS server requires secure file-lock requests, which require credentials from the client in order to lock a file. Most NFS clients send credentials with file lock requests, however, there are a few clients that do not send credentials when requesting a file-lock, allowing the client to only be able to lock world-readable files. To get around this, the "insecure_locks" option can be used so these clients can access the desired export. This poses a security risk by potentially allowing the client access to data for which it does not have authorization. Remove any instances of the "insecure_locks" option from the file "/etc/exports".
'
  tag checktext: '
To verify insecure file locking has been disabled, run the following command:

# grep insecure_locks /etc/exports


If there is output, this is a finding.
'

# START_DESCRIBE V-38677
  tag 'nfs','insecure_locks'
  describe command('grep insecure_locks /etc/exports') do
    its('stdout') { should eq "" }
  end
# END_DESCRIBE V-38677

end
