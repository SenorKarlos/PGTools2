################################
Supervisord (Linux)
################################

About Supervisord
=================
The purpose of supervisord is to monitor and control processes on UNIX-based
systems. In the context of RocketMap: start and manage instances and tools
(such as PGScout, PGPool etc). Thus upon boot, the instances and webserver will
be started, crashes will result in the instances being restarted and so on.
No need for tmux or screen to start the applications ;).

RocketMap CLI explanation
=========================
RocketMap basically offers two commandline-arguments to separate instances of
workers and webserver (as in the map/UI)

``--only-server``
    will start up a RocketMap instance with only the webserver.
    Thus no searchers/workers will be started and you can change static files
    without having your workers logout/login. The webserver itself simply reads
    the data in the SQL database configured in the configuration file.

``--no-server``
    will start a worker. No UI will be served. It will simply start
    searchers feeding data to the SQL database configured in the configuration file.

TL;DR

#.
    Modularise your search areas
#.
    Enables you to edit custom.js and stuff and run ``npm run build`` etc without
    a restart of your workers.


It is recommended to have only one --only-server instance run cleanup routines
btw.

Installation
============
`Supervisord docs <http://supervisord.org/installing.html#installing-a-distribution-package>`_

TL;DR:

On Ubuntu/Debian
``sudo apt-get install supervisor``


Basic configuration
===================
Simply place configurations in ``/etc/supervisor/conf.d/`` (path may differ
depending on your distribution).

Let's start with tools that we need:
``nano /etc/supervisor/conf.d/rm_tools.conf``

.. code-block:: bash

    [program:rm_webserver]
    command=/usr/bin/python /path/to/rocketmap/runserver.py --only-server -l 'WHATEVER LOCATION YOU WANT THE WEBSERVER TO POINT TO BY DEFAULT'
    user = www-data
    numprocs=1
    directory=/path/to/rocketmap/
    startsec=15
    startretries=3
    autorestart=true
    stopwaitsecs=5
    stdout_logfile=/path/for/log/rm_webserver.log
    redirect_stderr = true

Explanation of the above

``[program:rm_webserver]``
    this will be the name of the process for management
``command``
    should be self-explanatory. Simply the command supervisor will run
``user``
    the user supervisor will run the process as. www-data usually is the
    user your webserver (nginx/apache) uses.
``directory``
    is the directory the command is called in
``startsec, startretries, stopwaitsecs``
    these are timers that you usually
    should not need to touch
``stdout_logfile``
    specifies the path your log/output should be stored at
``redirect_stderr = true``
    will just put error-messages into the normal log

You can, of course, put pgpool, pgscout, devkat and any other ever-running tool
in a config.

When you are done setting up configs, run ``supervisorctl update``.
This will have supervisor read the configurations and detect changes and
additions.
Any changes will be applied by automatically restarting the applications and
additions will be started.

In order to get the output you would normally get from running the application
simply run ``tail -f /path/for/log/rm_webserver.log``.

Your webserver is running. Whenever you run ``npm run build``, simply call
``supervisorctl restart rm_webserver`` to restart the webserver.
A list of commands will be given below.

**Also do read the section regarding permissions!**

Now that you have a webserver running, add a searcher:

.. code-block:: bash

    [program:rm_areaXY]
    command=/usr/bin/python /opt/rocketmap/runserver.py -sn areaXY --no-server -l "locationToSearchAt" -speed -gf geofence.txt -st 27 -w 4
    directory=/opt/rocketmap/scanners/areaXY/
    user = www-data
    numprocs=1
    startsec=15
    startretries=3
    autorestart=true
    stopwaitsecs=5
    stdout_logfile=/tmp/rm_areaXY.log
    redirect_stderr = true

Explanation of the above

``[program:rm_areaXY]``
    will just give the process a different name. Name your
    search areas differently
``command``
    self explanatory. -sn will give the searcher a distinguishable name
    on the status-page. As you can see, you can just set the ordinary set of
    parameters (-speed, -gf and so on).
``directory``
    should point to a separate directory for the searcher. The
    directory will be spammed with matplotlib logfiles! Additionally, this
    makes managing geofence-files and stuff easier (pass relative paths).

Permissions
===========
Running the map or searchers as www-data requires the files to be owned/
accessible by www-data. In order to achieve that, run
``chown -R www-data:www-data /path/to/rocketmap/`` whenever you do a git pull
or run ``npm run build``.

Commands for supervisord
========================

*supervisorctl update*
    reread configurationfiles and start/stop/restart
    processes automatically

*supervisorctl status*
    shows all processes managed by supervisord as well
    as their uptime/status

*supervisorctl stop all*
    stops all processes managed by supervisord

*supervisorcrl start all*
    start all processes managed by supervisord

*supervisorctl restart all*
    restart all processes managed by supervisord

*supervisorctl start <processName>*
    starts the specified process. The name
    matches the one set in the config via the ``[program:processName]`` line.

*supervisorctl stop <processName>*
    see above.

*supervisorctl restart <processName>*
    see above.

Supervisord webUI
=================
Supervisord comes with a web-UI for easy management.
To enable it, run ``nano /etc/supervisor/supervisord.conf`` and change a couple
lines. Make the unix_http_server-block look like this:

.. code-block:: bash

    [unix_http_server]
    file=/var/run/supervisor.sock   ; (the path to the socket file)
    chmod=0700                       ; socket file mode (default 0700)
    chown=www-data:www-data

Optionally, you can add

.. code-block:: bash

    username = user
    password = 123

just below the above if you do not want to put basic-auth on the UI anyway.

In order to enable the UI, simply configure NGINX to serve the UI:

1.
    Set this outside a server-block

.. code-block:: bash

    upstream supervisor {
        server unix:/var/run/supervisor.sock fail_timeout=0;
    }


2.
    Set the location-block

.. code-block:: bash

    location / {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://supervisor;
        proxy_http_version 1.1;
        proxy_buffering     off;
        proxy_max_temp_file_size 0;
        proxy_redirect default;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Connection "";
    }


As you can see, the location-block already contains a auth_basic directive,
adjust it as needed.

Additional configuration-samples
================================

The configurations below are just examples and most likely require changes

.. code-block:: bash

    [program:pgpool]
    command=/usr/bin/python /opt/pgpool/pgpool.py
    user = www-data
    numprocs=1
    directory=/opt/pgpool/
    startsec=15
    startretries=3
    autorestart=true
    stopwaitsecs=5
    stdout_logfile=/tmp/pgpool.log
    redirect_stderr = true


.. code-block:: bash

    [program:devkat]
    command=/usr/bin/node /opt/pgtools/devkat/index.js
    user = www-data
    numprocs=1
    directory=/opt/pgtools/devkat/
    startsec=15
    startretries=3
    autorestart=true
    stopwaitsecs=5
    stdout_logfile=/tmp/devkat.log
    redirect_stderr = true
