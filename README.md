# SSHServer
This is a tutorial on how to build a basic SSH Server in C#. The wiki is a step by step process for setup with explanation of the various terms.

Please view the [Wiki](https://github.com/TyrenDe/SSHServer/wiki) for a full walkthrough!

For extra credit, I also ported the SSH Server to [NodeJS](https://github.com/TyrenDe/SSHServer/tree/master/SSHServerNodeJS).

Both samples get as far as sending and receiving encrypted packets.  It does not implement any SSH services such as user-auth.  But, after finishing the tutorial, adding new handlers for those packets and responding to them should be simple.

It also doesn't implement a variety of non-required algorithms.  I recommend extending your service to include more algorithm options.

- [C# SSHServer](https://github.com/TyrenDe/SSHServer/tree/master/src/SSHServer)
- [NodeJS SSHServer](https://github.com/TyrenDe/SSHServer/tree/master/SSHServerNodeJS)
