THE SOFTWARE IS PROVIDED "AS IS" AND VINZENT STEINBERG AND THE AUTHORS DISCLAIM
ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VINZENT STEINBERG OR THE AUTHORS
BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


# mpw

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

## Comparison to traditional stateful password managers

### Advantages

* Passwords are never stored
    * No brute force attacks against stored passwords possible
    * No synchronization over devices required

### Disadvantages

* Changing the master password requires changing all passwords
* Losing your master password compromises all passwords
  (for traditional managers you would have to lose your master password *and*
  the stored passwords)
* You can't use custom passwords
* You can't use custom password generation templates
