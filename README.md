THE SOFTWARE IS PROVIDED "AS IS" AND VINZENT STEINBERG AND THE AUTHORS DISCLAIM
ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VINZENT STEINBERG OR THE AUTHORS
BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


# mpw [![Build Status](https://travis-ci.org/vks/mpw-rs.svg?branch=master)](https://travis-ci.org/vks/mpw-rs)

A stateless password management solution.

This implements the [Master Password](https://ssl.masterpasswordapp.com/algorithm.html)
algorithm. It derives passwords for websites from your full name, the website's
name and your master password. Because of that, it is not necessary to store
any password.

## Status

This is mostly a toy project. It implements all features of the
[official C implementation](https://github.com/Lyndir/MasterPassword).
Additionally it can store the parameters required to derive the passwords in a
TOML file. It can also store encrypted passwords. (Of course this loses the
advantages over traditional password managers.)

## Examples

You need to specify all parameters for password generation via the command
line. The only exception is the master password, which is read interactively for
security reasons. For instance, let us suppose our full name is "John Doe" and
we want to generate a login password for github.com using the popular master
password "password":

    $ mpw --name "John Doe" github.com
    Please enter the master password:
    Identicon: ╔░╝⌚
    Password for github.com: VubeNazoRihe4(

The identicon is generated from your full name and your master password. It
serves as a visual indicator whether you made a typo while entering them. The
generated password is not random, it is deterministically derived from you full
name, your master password and the name of the site. Default parameters were
used when generating the password, you can change them via passing additional
command line parameters. See `mpw --help`.

For convenience, you can use a file to store the parameters of your passwords.
This is save, because the parameters are assumed to be public information. You
can also store encrypted, user-defined passwords in this file. Doing this
corresponds to using a traditional stateful password manager. An example:

    $ mpw --config passwords.toml --name "John Doe" --add github.com
    $ mpw --config passwords.toml --store wikipedia.org
    Please enter the master password:
    Identicon: ╔░╝⌚
    Please enter the site password to be stored:
    $ mpw --config passwords.toml
    Please enter the master password:
    Identicon: ╔░╝⌚
    Password for github.com: VubeNazoRihe4(
    Password for wikipedia.org: secret
    $ cat passwords.toml
    full_name = "John Doe"

    [[sites]]
    name = "github.com"

    [[sites]]
    encrypted = "yyCo1ILGvCYn6o8jvcOslbwMaU2Gf02zxoYR2apYc9Fn0s0+HH7Czgk+6slb6Xsz"
    name = "wikipedia.org"
    type = "stored"

The keywords in the config are the same as the for long command line parameters.

## Comparison to traditional stateful password managers

### Advantages

* Passwords are never stored
    * No brute force attacks against stored passwords possible
    * No synchronization of devices required

### Disadvantages

* Changing the master password requires changing all passwords
* Losing your master password compromises all passwords
  (for traditional managers you would have to lose your master password *and*
  the stored passwords)
* You can't use custom passwords
* You can't use custom password generation templates
