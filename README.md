# GvcpServer
本项目实现了一种基于GVCP协议和mjpeg-steamer的网口工业相机。使用GigeVision中的gvcp协议来实现对相机的发现，修改IP和远程控制功能，使用mjpeg-steamer来传输图像数据.配合PC端的OpenMVS软件使用，可以方便的查找相机、管理相机、获取图像，保存图片等功能。  
已测试通过的开源硬件链接为 https://item.taobao.com/item.htm?id=652142910541  
This project implements a network port industrial camera based on GVCP protocol and MJPEG steamer. The GVCP protocol in GigE Vision is used to discover the camera, modify the IP and remote control functions, and mjpeg-steamer is used to transmit image data. Combined with the OpenMVS software on the PC side, it can easily find the camera, manage the camera, obtain images, save pictures and other functions. The tested open source camera link is
# 使用方法step：
git clone https://github.com/BigSensor/GvcpServer  
cd GvcpServer  
make  
./GvcpServer  
