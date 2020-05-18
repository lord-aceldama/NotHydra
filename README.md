# NotHydra
This is not THC Hydra. It is a substitute to simplify the hydra brute-forcing process by
automating form retrieval and allowing seamless TOR integration.

# Install
```sh
git clone https://github.com/lord-aceldama/NotHydra.git
cd NotHydra
bash install
```

After the installation is complete, you can launch NotHydra by typing `NotHydra`, which
will show the welcome and help screen.

# Example usage:
## Verify that TOR is working
To verify that your traffic gets routed over TOR, the `-ip` command can be used alongside
the `-tor` command. By default the tor service runs on `localhost:9050`, but if you set it
up differntly then you'll need to adjust the parameter accordingly.
``` sh
NotHydra -ip -tor localhost:9050
```

# License 
This software is licensed under the [MIT License](LICENSE.txt).