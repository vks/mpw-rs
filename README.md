# mpw

A stateless password management solution.

This implements the [Master Password](http://masterpasswordapp.com/algorithm.html)
algorithm. It derives password for websites from your full name, the website's
name and your master password.

**Warning**: This is not very well tested or audited for security issues. Use at
your own risk.

## Comparison to traditional stateful password managers

## Advantages

* Passwords are never stored
    * No brute force attacks against stored passwords possible
    * No synchronization over devices required
* Entering a different master password gives different passwords
  (could be used for plausible deniability)

## Disadvantages

* Changing the master password requires changing all passwords
* Losing your master password compromises all passwords
  (for traditional managers you would have to lose your master password *and*
  the stored passwords)
* You can't use custom passwords
* You can't use custom password generation templates
