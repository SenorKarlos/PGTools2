################################
Install Prerequisite 2 - PGScout
################################

About PGScout
=============
   PGScout is a tool that enables the IV scanning of Pokemon.  It makes use of level 30 accounts which are pulled from
   :ref:`PGPool <Install Prerequisite 1 - PGPool>`.  Unlike the IV scanning in the standard RocketMap, PGScout is
   a lot more efficient at IVs encounters.  This means that you need less lvl30 scanning accounts.  It also has the
   option to allow map users to scan the IVs of Pokemon that aren't included in the IV scan list.

   Before continuing with this document please make sure that you have got :ref:`PGPool <Install Prerequisite 1 - PGPool>`
   running completely and that it has at least one lvl30 account in the pool as only lvl30 or greater accounts are used
   for IV scanning.

PGScout Detailed Install
========================
   For a quick instructions on how to install PGScout refer to the :ref:`pgscout-tldr` section.  This section provides a bit more
   details about what each program actually does.  Remember that it is already assumed that you have followed all the
   steps in the :ref:`PGPool <Install Prerequisite 1 - PGPool>`.  If not, stop reading this and complete the steps mentioned
   there.

#. **Download and setup PGScout**

   Download the source code of PGScout into your desired location. We will use /root/rm-alt in this docs as the
   installation directory of choice.

   .. code-block:: bash

      git clone https://github.com/SenorKarlos/PGScout.git
      cd PGScout
      pip install -r requirements.txt
      cp config.ini.sample config.ini

   Once that is done open `config.ini` using your favorite editor and change the host and port details.  The host
   should match where you have installed PGPool (which will be 127.0.0.1 as it is on the same server 99% of the time).
   The port number can be anything so long as it isn't in use already.

   .. image:: _static/images/pgscout-config1.gif

   Next you need to add your hashing key from Bossland.  If your IP is banned you will also need to add your proxies
   details.  This docs will assume you have a file called `proxies.txt`.  Lastly set the Shadowban-threshold to 0.
   This is because currently lvl30 accounts do not get "shadow bans".  They get out right bans (ie: they can't even
   log in) which means you, at least for now, do not need to worry about the Shadow bans.

   .. image:: _static/images/pgscout-config2.gif

   For this example the `proxies.txt` file will look something like this:

   .. code-block:: bash

      123.123.123.123:8080
      456.456.456.456:8181
      789.789.789.789:8282

   The last bit of the config deals with informing PGScout where PGPool is.  PGPool is responsible for providing the
   lvl30 accounts to PGPool.  So you will need to add the port that PGPool is currently assigned to.  From our last
   example that was 4242.  `pgpool-system-id` can be any value.  However if you have multiple instances of PGScout
   running you should ensure that each instance has its own value.  This ensures that each of the lvl30 accounts
   are linked to each of the PGScout instances and not shared.  Lastly `pgpool-num-accounts` is the number of lvl30
   accounts that PGScout will use.

   .. image:: _static/images/pgscout-config3.gif

.. _pgscout-tldr:

PGScout tl;dr Install
=====================

   .. code-block:: bash

      git clone https://github.com/SenorKarlos/PGScout.git
      cd PGScout
      pip install -r requirements.txt
      cp config.ini.sample config.ini

   At least the following needs to be added to the `config.ini` file:

   .. code-block:: bash

      host: 127.0.0.1                   # Host or IP to bind to.
      port: 4243                        # Port that PGPool will be to bind to.
      hash-key: 9E4R0S1M2K6I1Y4H1V8X    # Bossland hashkey (this hashkey is invalid)
      pgpool-url: http://127.0.0.1:4242 # Location of PGPool (with it's port)
      pgpool-system-id: PGPool1         # System ID for PGPool.
      pgpool-num-accounts: 5            # Number of accounts PGScout will use

PGScout Final Notes
===================

   PGScout is only needed if you require IV scanning.  Each lvl30 account can on average find 1300 Pokemon
   IVs per hour.  Once PGPool and PGScout are fully setup you will need to provide add the location and ports
   to the main RM-Alt program.  