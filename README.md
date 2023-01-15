# 2FA for MacOS

Once built, will generate a .app file that can be installed anywhere appropriate, e.g. in ~/Applications/


### Storing new seeds

To add a new seed, use `set` with an alias and the seed data:
```
$ ~/Applications/2FA.app/Contents/MacOS/2FA set some-site ABCXYZ...
Set seed for some-site
```

or use a seed of `-` to read from the command line:
```
$ ~/Applications/2FA.app/Contents/MacOS/2FA set some-site -
Seed (max 255 chars):     # (charcaters typed won't be shown)
Set seed for some-site
```

Updating the seed for any reason can be done by reissuing the command - the previous seed will be overwritten for that key:
```
$ ~/Applications/2FA.app/Contents/MacOS/2FA set some-site ABC123...
Found existing seed for some-site - will update to new seed
Updated seed for some-site
```

### Generating TOTPs

```
$ ~/Applications/2FA.app/Contents/MacOS/2FA get some-site
           # (A biometric or login-password local authentication dialogue is presented at this point)
192847
```

Currently all TOTPs generated are with SHA1, a period of 30 seconds, and for 6 digits.

