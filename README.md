### Simple Anchore CLI UI

##### What is anchoresi
Anchoresi is a very basic webinterface which talks to your Anchore platform API.
Current support are basic functions like image overview, vulnerability overview, adding and deleting images from the platform.

##### What is Anchore?
Anchore is a tool and/or platform to analyse container images for vulnerabilities and matching compliance.
You can host a platform [yourself][anchore github ref] or you could use the [Anchore SAAS offering][anchore saas ref].

##### Why would I use this anchoresi?
This is a webinterface which is capable of handeling the basic CRUD actions on your Anchore platform instead of using the anchore-cli tool. 

##### How do I get started with Anchore?
To hit the ground running use the Anchore SAAS offering. To host a cluster yourself e.g on a kubernetes cluster checkout [github deployment pages][anchore github ref].

##### Some screenshots of the anchoresi project.
<u>System Status</u>
![alt text](https://github.com/pblaas/anchoresi/blob/master/AnchoreUI-screenshot1.png "System status")
<u>Image Overview</u>
![alt text](https://github.com/pblaas/anchoresi/blob/master/AnchoreUI-screenshot2.png "Image overview")


[anchore saas ref]: https://anchore.com/
[anchore github ref]: https://github.com/anchore/anchore_deployment

##### Running the app.
To run the app you need to set 3 environment variables.
```
export URL=https://anchore.YOURIP.nip.io
export USERNAME=admin
export PASSWORD=YOURPASSWORD HERE
```
Next you can start the Flask microframework.
```
python app.py
```

##### Using the Docker container.
A docker container will be automaticly build after updating the application code. To use this container you need to provide environment flags

```
docker run -p 5000:5000 \
-e URL=https://anchore.YOURIP.nip.io \
-e USERNAME=admin \
-e PASSWORD=YOURPASSWORDHERE \
 pblaas/anchoresi:latest
```

