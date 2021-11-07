// Author: Ryan Cobb (@cobbr_io)
// Project: LemonSqueezy (https://github.com/cobbr/LemonSqueezy)
// License: GNU GPLv3

using System;
using System.Collections.Generic;

namespace LemonSqueezy.Core
{
    public class LemonSqueezyException : Exception
    {
        public LemonSqueezyException() : base()
        {

        }
        public LemonSqueezyException(string message) : base(message)
        {

        }
    }

    public class ControllerException : Exception
    {
        public ControllerException() : base()
        {

        }
        public ControllerException(string message) : base(message)
        {

        }
    }

    public class ControllerNotFoundException : Exception
    {
        public ControllerNotFoundException() : base()
        {

        }
        public ControllerNotFoundException(string message) : base(message)
        {

        }
    }

    public class ControllerBadRequestException : Exception
    {
        public ControllerBadRequestException() : base()
        {

        }
        public ControllerBadRequestException(string message) : base(message)
        {

        }
    }

    public class ControllerUnauthorizedException : Exception
    {
        public ControllerUnauthorizedException() : base()
        {

        }
        public ControllerUnauthorizedException(string message) : base(message)
        {

        }
    }

    public class LemonSqueezyDirectoryTraversalException : Exception
    {
        public LemonSqueezyDirectoryTraversalException() : base()
        {

        }
        public LemonSqueezyDirectoryTraversalException(string message) : base(message)
        {

        }
    }

    public class LemonSqueezyLauncherNeedsListenerException : LemonSqueezyException
    {
        public LemonSqueezyLauncherNeedsListenerException() : base()
        {

        }
        public LemonSqueezyLauncherNeedsListenerException(string message) : base(message)
        {

        }
    }

    public class LemonSqueezyCompileMofoStagerFailedException : LemonSqueezyException
    {
        public LemonSqueezyCompileMofoStagerFailedException() : base()
        {

        }
        public LemonSqueezyCompileMofoStagerFailedException(string message) : base(message)
        {

        }
    }
}
