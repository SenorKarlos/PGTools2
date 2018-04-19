##############
Install RM-Alt
##############

About RM-Alt
============
   This fork is very similar to the main Rocket Map project.  However it does require a few different settings.  If you
   are migrating over from the main RM project it is recommended that you run a complete db init (ie: remove your
   current database and start over).

   Before continuing with this doc you will need to have :ref:`PGPool <Install Prerequisite 1 - PGPool>` running
   and if you are scanning for IVs you will also need :ref:`PGScout <Install Prerequisite 2 - PGScout>` setup.

RM-Alt Detailed Install
=======================

   #. **Download and install requirements**
      You will need to get the code for Rocket Map.  This doc will assume that you use the `/root/rm-alt/` folder.

      .. code-block:: bash

         cd /root/rm-alt/
         git clone https://github.com/SenorKarlos/RocketMap.git
         cd RocketMap
         pip install -r requirements.txt

   #. **Setting up MySql**
      As was previously done in PGPool you will also need to create a new database for Rocket Map Alt.  This
      database will be storing all the data that is used to display your map. This
      document will use the database "rocketMapAlt".  You will now need to log into MySql. (As mentioned earlier,
      this document will assume the password `DontUseThisPassword123` for the root MySql user.)

      .. code-block:: bash

         mysql -uroot -pDontUseThisPassword123

      Once logged into MySql you need to create a database called `rocketMapAlt`.

      .. code-block:: mysql

         CREATE DATABASE rocketMapAlt;

      Make sure the database is there.  Note: There might already be other databases already there.  You just need to
      make sure that at least one database is called *rocketMapAlt*.

      .. code-block:: mysql

         SHOW databases;

      You should see something like this (again look for the table *rocketMapAlt*)

      .. code-block:: mysql

         +--------------------+
         | Database           |
         +--------------------+
         | information_schema |
         | mysql              |
         | performance_schema |
         | pgpool             |
         | rocketMapAlt       |
         | sys                |
         +--------------------+

      Once you've confirmed that the database `rocketMapAlt` exists you can then exit MySql by simply typing:

      .. code-block:: mysql

         exit;


   #. **Edit config settings**
      We now need to provide a link to where PGPool is installed so that the scanning accounts can be pulled from
      PGPool.  Also if you want to scan for IVs you will also need to provide a link to where PGScout is setup.

      .. code-block:: bash

         cp config/config.ini.example config/config.ini

      The first two lines provide a link from the PGTools (PGPool and PGScout) to Rocket Map.  It is also highly
      advisable to set some sort of "limit" to the number of "scans" an account can do without seeing any Pokemon
      that are not on the Shadow Ban list.  A good value to use is 4.  This means that the accounts will search
      their surroundings 4 times.  If after 4 times that account has only seen Pokemon on the "Shadow Ban" list
      it will automatically be flagged as "Shadow Banned" and then removed from PGPool.  For initial scannings a value
      of 10 would be recommended. The rotate-blind makes sure to remove blind accounts from your pool.

      .. code-block:: text

         pgpool-url: http://127.0.0.1:4242
         pgscout-url: http://127.0.0.1:4243/iv
         rareless-scans-threshold: 4
         rotate-blind: true

RM-Alt tl;dr
============
   .. code-block:: bash

      #download source code and install requirements.
      cd /root/rm-alt/
      git clone https://github.com/SenorKarlos/RocketMap.git
      cd RocketMap
      pip install -r requirements.txt

      #add mysql database
      mysql -uroot -pDontUseThisPassword123
      CREATE DATABASE rocketMapAlt;
      exit;

   Here is a sample config file for a map.  Replace all XXXX with your values.

   .. code-block:: text

      sdfg
      sdfg

RM-Alt Configuration File
=========================

   It is recommend to try and put all your settings into the config file.  That way you can run a simple and neat
   `python2.7 runserver.py -H 0.0.0.0 -cf config/config.ini` command.  Here is a list of all the specific
   config commands you can have in your config file and what they do.

   +-------------------+-------------------------------------------------------+------------------------------------+
   | Config Name       | Config Explanation                                    | Config Example                     |
   +-------------------+-------------------------------------------------------+------------------------------------+
   | pgpool-url        | Provides the address and port of the PGPool instance  | http://127.0.0.1:4242              |
   |                   | so that accounts are loaded into RM.                  |                                    |
   |                   |                                                       |                                    |
   +-------------------+-------------------------------------------------------+------------------------------------+

   1. **pgpool-url:** Provides the address and port of the PGPool instance so that accounts are loaded into RM. Example:
    http://127.0.0.1:4242