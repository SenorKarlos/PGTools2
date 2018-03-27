###############################
Install Prerequisite 1 - PGPool
###############################

About PGPool
============
PGPool will be used to keep track of all your accounts/workers.  Instead of dealing with text files that you need to
update every few days when accounts get banned or if you need to add extra level 30 workers for IV scanning, PGPool
will help to automate this process.  Basically say goodbye to manually loading and removing workers every few days.

PGPool will instead create a database where all these accounts are stored and it will automatically "remove" banned
or blinded accounts.


Detailed Install
================
For a quick instructions on how to install PGPool refer to the :ref:`tldr` section.  This section provides a bit more
details about what each program actually does.

#. **Git**

   First we need `git`_ installed.  This program is used to download and keep the code for PGPool up to date.

   .. code-block:: bash

      sudo apt-get update
      sudo apt-get install git-core

   Once completed check that it is installed by typing:

   .. code-block:: bash

      ~$ git --version
      git version 2.7.4

#. **Python**

   Next we need `python`_ installed.  This program is used to run the actual code that we will download from Github.

   .. code-block:: bash

      sudo apt-get install -y python python-pip python-dev build-essential git libssl-dev libffi-dev
      curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
      sudo apt-get install -y nodejs
      sudo pip install --upgrade pip

   Once installed check that you have at least version 2.7 of Python.

   .. code-block:: bash

      ~$ python --version
      Python 2.7.12
      ~$ pip --version
      pip 9.0.3 from /usr/local/lib/python2.7/dist-packages (python 2.7)

#. **MySql**

   Lastly we need to install MySql and create a database called `pgpool`.  This is where all the accounts will
   be stored instead of a text file.

   .. code-block:: bash

      sudo apt-get install mysql-server

   You will be prompted for a password.  Type down a password of your choice and be sure to remember it.  For this doc
   we will be using the password *DontUseThisPassword123*

   You will now need to log into MySql.

   .. code-block:: bash

      mysql -uroot -pDontUseThisPassword123

   Once logged into MySql you need to create a database called `pgpool`.

   .. code-block:: mysql

      CREATE DATABASE pgpool;

   Make sure the database is there.  Note: There might already be other databases already there.  You just need to
   make sure that at least one database is called *pgpool*.

   .. code-block:: mysql

      SHOW databases;

   You should see something like this (again look for the table *pgpool*)

   .. code-block:: mysql

      +--------------------+
      | Database           |
      +--------------------+
      | information_schema |
      | mysql              |
      | performance_schema |
      | pgpool             |
      | sys                |
      +--------------------+

#. **Download and setup PGPool**

   Download the source code of PGPool into your desired location.  We will use `/root/rm-alt` in this docs as the
   installation directory of choice.

   .. code-block:: bash

      mkdir /root/rm-alt
      cd /root/rm-alt
      git clone https://github.com/SenorKarlos/PGPool.git

   Once git has downloaded the code we can go into the newly created folder install some required 3rd party programs.

   .. code-block:: bash

      cd /root/rm-alt/PGPool
      pip install -r requirements.txt
      cp config.json.sample config.json

   Once PGPool has installed its 3rd party libraries we can now setup the configuration for it.  Use your
   preferred text editor, this example shown in the gif below, will use *vim* to change the database user and the
   database name.  Obviously make sure to use your own database username and your own database password.

   .. code-block:: bash

      vim config.json

   .. image:: _static/images/pgpool-edit-config.gif

   Once you have updated your login details you can test run the program to see if it is working.

   .. code-block:: bash

      python pgpool.py

   It should give some output as follows (only the first run will it have the "creating table" text):

   .. code-block:: bash

      [    INFO] PGPool starting up...
      [    INFO] Webhook disabled.
      [    INFO] Connecting to MySQL database on localhost:3306...
      [    INFO] Creating table: Account
      [    INFO] Creating table: Event
      [    INFO] Creating table: Version
      [    INFO] Changing collation and charset on database.
      [    INFO] Changing collation and charset on 3 tables.
      [    INFO] Starting auto-release thread releasing accounts every 120 minutes.

   The next section will deal with loading accounts into PGPool.

.. _tldr:

tl;dr Install
=============
   .. code-block:: bash

      #install git
      apt-get update
      apt-get install -y git-core

      #install python
      sudo apt-get install -y python python-pip python-dev build-essential git libssl-dev libffi-dev
      curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
      sudo apt-get install -y nodejs
      sudo pip install --upgrade pip

      #install MySql
      sudo apt-get install -y mysql-server
      #This example assumes the password is DontUseThisPassword123
      mysql -uroot -pDontUseThisPassword123
      CREATE DATABASE pgpool;
      exit

      #Download and setup PGPool
      mkdir /root/rm-alt
      cd /root/rm-alt
      git clone https://github.com/SenorKarlos/PGPool.git
      cd /root/rm-alt/PGPool
      pip install -r requirements.txt
      cp config.json.sample config.json
      #as mentioned this example assumes the password is DontUseThisPassword123 and username is root
      sed -i 's/<DB USER>/root/g' config.json
      sed -i 's/<DB PASS>/DontUseThisPassword123/g' config.json

Adding Accounts into PGPool
===========================

   Once PGPool is setup you can load accounts into it.  To lvl0 to lvl29 accounts you should
   create a text file that has all your accounts in it.  It should look something like this:

   .. code-block:: bash

      accountName1:accountPassword1
      accountName2:accountPassword3
      accountName3:accountPassword3

   This doc will assume you have named you filed lowLevel.txt to store all your accounts that are level 0 to
   level 29.  You can import your accounts into PGPool by then running:

   .. code-block:: bash

      python pgpool-import.py -i lowLevel.txt -l 1 -cnd good

   To load IV scanning accounts (which obviously need to be level 30 to 40) simply change the previous
   command's "1" to a "30" and give the correct filename of where you have those accounts.  This doc will assume all
   level 30 to 40 accounts are loaded in a file called `highLevel.txt`

   .. code-block:: bash

      python pgpool-import.py -i highLevel.txt -l 30 -cnd good


Final Notes
===========

   PGPool will need to be continuously running in the background so that it can load accounts into RM-Alt
   and/or PGScout.  The use of the program `screen`_ is highly recommended for this.

   As soon as an account is shadow banned, PGPool will no longer allow that account to be active and will remove it
   from the pool.  This means that you don't need to manually add accounts every few days for scanning.  You simply
   load in a large amount into the database and let it run until all the accounts are banned.

   You can see a detailed output of pgpool by hitting the `enter key` while running pgpool.  It looks something like
   this:

   .. image:: _static/images/pgpool-details.png

.. _git: https://git-scm.com/
.. _python: https://www.python.org/about/
.. _screen: https://www.gnu.org/software/screen/