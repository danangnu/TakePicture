#include "stdafx.h"

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/algorithm/string.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <opencv2/opencv.hpp>
#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/imgcodecs.hpp>
#include <cppcodec/base32_crockford.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <comdef.h>
#include <wbemidl.h>
#include <dshow.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <string>
#include <locale>
#include <codecvt>
#include <cctype>

#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "wbemuuid.lib") // Required for WMI

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = net::ip::tcp;

#include <boost/asio/ssl.hpp>
namespace ssl = boost::asio::ssl;

using namespace cv;

// Base64 encoding using cppcodec
std::string base64Encode(const std::vector<uchar>& data) {
	return cppcodec::base64_rfc4648::encode(data.data(), data.size());
}


std::wstring removeCharactersBeforeSubstring(const std::wstring& input, const std::wstring& substring) {
	size_t position = input.find(substring);
	if (position != std::wstring::npos) {
		position += substring.length(); // Move position after the substring.
		return input.substr(position);
	}
	// If the substring is not found, return an empty wstring.
	return L"";
}

std::wstring removeSubstringAfterCharacters(const std::wstring& input, const std::wstring& characters) {
	size_t position = input.find(characters);
	if (position != std::wstring::npos) {
		return input.substr(0, position);
	}
	// If the characters are not found, return the original string.
	return input;
}

std::wstring takeSubstringBeforeCharacter(const std::wstring& input, char character) {
	size_t position = input.find(character);
	if (position != std::wstring::npos) {
		return input.substr(0, position);
	}
	// If the character is not found, return the original string.
	return input;
}

std::wstring takeSubstringBetweenCharacters(const std::wstring& input, char startChar, char endChar) {
	size_t startPos = input.find(startChar);
	if (startPos != std::wstring::npos) {
		size_t endPos = input.find(endChar, startPos + 1);
		if (endPos != std::wstring::npos) {
			return input.substr(startPos + 1, endPos - startPos - 1);
		}
	}
	// If the characters are not found or there is an error, return an empty string.
	return L"";
}

int findCameraIndexByDeviceID(const std::wstring& deviceId) {
	int cameraIndex = -1;

	HRESULT hres;

	// Step 1: Initialize COM
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		std::cerr << "Failed to initialize COM library. Error code: " << hres << std::endl;
		return cameraIndex;
	}

	// Step 2: Initialize WMI
	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities
		NULL                         // Reserved
	);

	if (FAILED(hres)) {
		std::cerr << "Failed to initialize security. Error code: " << hres << std::endl;
		CoUninitialize();
		return cameraIndex;
	}

	// Step 3: Obtain the WMI connection
	IWbemLocator* pLoc = nullptr;
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID*)&pLoc
	);

	if (FAILED(hres)) {
		std::cerr << "Failed to create IWbemLocator object. Error code: " << hres << std::endl;
		CoUninitialize();
		return cameraIndex;
	}

	// Step 4: Connect to WMI through the IWbemLocator::ConnectServer method
	IWbemServices* pSvc = nullptr;
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),  // WMI namespace
		NULL,                     // User name
		NULL,                     // User password
		0,                        // Locale
		NULL,                     // Security flags
		0,                        // Authority
		0,                        // Context object
		&pSvc                    // IWbemServices proxy
	);

	if (FAILED(hres)) {
		std::cerr << "Failed to connect to WMI. Error code: " << hres << std::endl;
		pLoc->Release();
		CoUninitialize();
		return cameraIndex;
	}

	// Step 5: Set the WMI proxy so that impersonation of the user (if needed) occurs.
	hres = CoSetProxyBlanket(
		pSvc,                         // WbemServices proxy
		RPC_C_AUTHN_WINNT,            // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,             // RPC_C_AUTHZ_xxx
		NULL,                         // Server principal name
		RPC_C_AUTHN_LEVEL_CALL,       // RPC_C_AUTHN_LEVEL_xxx
		RPC_C_IMP_LEVEL_IMPERSONATE,  // RPC_C_IMP_LEVEL_xxx
		NULL,                         // client identity
		EOAC_NONE                     // proxy capabilities
	);

	if (FAILED(hres)) {
		std::cerr << "Failed to set proxy blanket. Error code: " << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return cameraIndex;
	}

	// Step 6: Query for Win32_PnPEntity class to get device information
	IEnumWbemClassObject* pEnumerator = nullptr;
	std::wstring devone = removeCharactersBeforeSubstring(deviceId, L"USB#");
	std::wstring devtwo = removeSubstringAfterCharacters(devone, L"#{");
	std::wstring devTakeOne = takeSubstringBeforeCharacter(devtwo, '&');
	std::wstring devTakeTwo = takeSubstringBetweenCharacters(devtwo, '&', '#');
	std::wstring query = L"SELECT * FROM Win32_PnPEntity WHERE DeviceID like 'USB%' AND DeviceID like '%" + devTakeOne + L"%' AND DeviceID like '%" + devTakeTwo + L"%' AND PNPClass = 'Camera'";
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(query.c_str()),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	if (FAILED(hres)) {
		std::cerr << "Failed to execute WQL query. Error code: " << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return cameraIndex;
	}

	// Step 7: Get the device index from the query result
	ULONG uReturn = 0;
	IWbemClassObject* pclsObj;
	while (pEnumerator) {
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn)
			break;

		VARIANT vtProp;
		hres = pclsObj->Get(L"Index", 0, &vtProp, 0, 0);
		if (SUCCEEDED(hres)) {
			cameraIndex = vtProp.intVal;
			VariantClear(&vtProp);
		}
		pclsObj->Release();
	}

	// Clean up
	pSvc->Release();
	pLoc->Release();
	CoUninitialize();

	return cameraIndex;
}

std::string getCameraHardwareID(std::string deviceId) {
	std::string hardwareID;
	HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		std::cout << "Failed to initialize COM library" << std::endl;
		return "";
	}

	IWbemLocator* pLoc = NULL;
	hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

	if (FAILED(hr)) {
		std::cout << "Failed to create IWbemLocator object" << std::endl;
		CoUninitialize();
		return "";
	}

	IWbemServices* pSvc = NULL;
	hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);

	if (FAILED(hr)) {
		std::cout << "Failed to connect to WMI namespace" << std::endl;
		pLoc->Release();
		CoUninitialize();
		return "";
	}

	hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

	if (FAILED(hr)) {
		std::cout << "Failed to set proxy blanket" << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return "";
	}

	IEnumWbemClassObject* pEnumerator = NULL;
	hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_PnPEntity"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

	if (FAILED(hr)) {
		std::cout << "Failed to execute WMI query" << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return "";
	}

	IWbemClassObject* pclsObj;
	ULONG uReturn = 0;

	while (pEnumerator) {
		hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (0 == uReturn)
			break;

		VARIANT vtProp;
		hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);

		if (SUCCEEDED(hr)) {
			std::wstring wstrID(vtProp.bstrVal, SysStringLen(vtProp.bstrVal));
			std::string strID(wstrID.begin(), wstrID.end());

			if (strID.find("VID_") != std::string::npos && strID.find("PID_") != std::string::npos) {
				std::string currentDeviceId = strID.substr(strID.find("VID_") + 4, 4);

				if (currentDeviceId == deviceId) {
					hardwareID = strID;
					VariantClear(&vtProp);
					break;
				}
			}
			VariantClear(&vtProp);
		}
		pclsObj->Release();
	}

	pEnumerator->Release();
	pSvc->Release();
	pLoc->Release();
	CoUninitialize();

	return hardwareID;
}

int GetCameraCount()
{
	IWbemLocator* pLoc = nullptr;
	IWbemServices* pSvc = nullptr;
	IEnumWbemClassObject* pEnumerator = nullptr;

	ULONG usbDeviceCount = 0;

	// Initialize COM
	CoInitializeEx(nullptr, COINIT_MULTITHREADED);

	HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

	if (SUCCEEDED(hr))
	{
		hr = pLoc->ConnectServer(
			_bstr_t(L"ROOT\\CIMV2"),
			nullptr,
			nullptr,
			0,
			NULL,
			0,
			0,
			&pSvc);

		if (SUCCEEDED(hr))
		{
			hr = CoSetProxyBlanket(
				pSvc,
				RPC_C_AUTHN_WINNT,
				RPC_C_AUTHZ_NONE,
				nullptr,
				RPC_C_AUTHN_LEVEL_CALL,
				RPC_C_IMP_LEVEL_IMPERSONATE,
				nullptr,
				EOAC_NONE);

			if (SUCCEEDED(hr))
			{
				std::wstring query = L"SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'Camera'";
				hr = pSvc->ExecQuery(
					bstr_t("WQL"),
					bstr_t(query.c_str()),
					WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
					nullptr,
					&pEnumerator);

				if (SUCCEEDED(hr))
				{
					// Count the USB devices
					IWbemClassObject *pObj = NULL;
					while (true) {
						ULONG returnedCount = 0;
						hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returnedCount);
						if (hr != WBEM_S_NO_ERROR || returnedCount == 0) {
							break;
						}
						usbDeviceCount++;
						pObj->Release();
					}
				}
			}
		}
	}
	return usbDeviceCount;
}

bool capturing = false;

void onCaptureButtonClick(int event, int x, int y, int flags, void* userdata) {
	if (event == cv::EVENT_LBUTTONDOWN) {
		capturing = true;
	}
}

std::string removeCharactersBeforeSubstring(const std::string& input, const std::string& substring) {
	size_t position = input.find(substring);
	if (position != std::string::npos) {
		position += substring.length(); // Move position after the substring.
		return input.substr(position);
	}
	// If the substring is not found, return an empty wstring.
	return "";
}

std::string removeSubstringAfterCharacters(const std::string& input, const std::string& characters) {
	size_t position = input.find(characters);
	if (position != std::string::npos) {
		return input.substr(0, position);
	}
	// If the characters are not found, return the original string.
	return input;
}

std::string takeSubstringBeforeCharacter(const std::string& input, char character) {
	size_t position = input.find(character);
	if (position != std::string::npos) {
		return input.substr(0, position);
	}
	// If the character is not found, return the original string.
	return input;
}

void runCamerabyName(std::string &selectedCamera, std::string &selectedVid, std::string &selectedPid) {
	int cCount = GetCameraCount();
	for (int i = 0; i < GetCameraCount(); ++i) {
		std::string camName{};
		std::string vid{};
		std::string pid{};

		// Convert str2 to lowercase
		for (char &c : selectedCamera) {
			c = std::tolower(c);
		}
		//if (cap.isOpened()) {

		// Get the capture graph builder
		// Initialize COM
		CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

		// Enumerate video capture devices
		ICreateDevEnum *pDevEnum;
		CoCreateInstance(CLSID_SystemDeviceEnum, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pDevEnum));

		IEnumMoniker *pEnum;
		pDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEnum, 0);

		IMoniker *pMoniker = NULL;

		int cameraIndex = 0;
		while (pEnum->Next(1, &pMoniker, NULL) == S_OK) {
			if (cameraIndex == i) {
				// Get the camera's friendly name using DirectShow
				IPropertyBag *pPropBag;
				pMoniker->BindToStorage(0, 0, IID_PPV_ARGS(&pPropBag));

				VARIANT varName;
				VariantInit(&varName);
				VARIANT devPath;
				VariantInit(&devPath);

				// Retrieve the friendly name
				pPropBag->Read(L"FriendlyName", &varName, 0);
				pPropBag->Read(L"DevicePath", &devPath, 0);
				std::wstring wideName(varName.bstrVal);
				std::wstring wideDev(devPath.bstrVal);
				std::string friendlyName(wideName.begin(), wideName.end());
				std::string devicePath(wideDev.begin(), wideDev.end());
				std::string devone = removeCharactersBeforeSubstring(devicePath, "usb#");
				std::string devvid = takeSubstringBeforeCharacter(devone, '&');
				devvid = removeCharactersBeforeSubstring(devicePath, "vid_");
				devvid = removeSubstringAfterCharacters(devvid, "&");
				std::string devpid = removeCharactersBeforeSubstring(devone, devvid + "&");
				devpid = removeSubstringAfterCharacters(devpid, "&");
				devpid = removeCharactersBeforeSubstring(devpid, "pid_");
				for (char &c : friendlyName) {
					c = std::tolower(c);
				}
				if (selectedCamera == friendlyName && selectedVid == devvid && selectedPid == devpid) {
					camName = friendlyName;
					vid = devvid;
					pid = devpid;
				}

				VariantClear(&varName);
				pPropBag->Release();
			}

			pMoniker->Release();
			cameraIndex++;
		}

		pEnum->Release();
		pDevEnum->Release();

		// Uninitialize COM
		CoUninitialize();
		if (camName == selectedCamera && selectedVid == vid && selectedPid == pid) {

			Mat frame;
			VideoCapture cap(i);
			if (cap.isOpened()) {
			bool isTrue = true;

			namedWindow("Camera Capture");

			try {
			setMouseCallback("Camera Capture", onCaptureButtonClick, NULL);
			}
			catch (cv::Exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
			}

			// Start capturing frames from the camera.
			while (isTrue) {
			cap >> frame;


			// Display the frame.
			imshow("Camera Capture", frame);

			if (capturing) {
			std::string filename = "captured_image.jpg";
			imwrite(filename, frame);
			std::cout << "Image captured and saved as " << filename << std::endl;
			capturing = false;
			break;
			}

			char key = cv::waitKey(10);
			if (key == 27) // Press Esc to exit
			break;


			}
			}
			cap.release();
			cv::destroyAllWindows();

		}

		//}
	}
}

void usingUnsecureWS() {
	try {
		net::io_context ioc;
		tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 8080));

		while (true) {
			tcp::socket socket(ioc);
			acceptor.accept(socket);

			websocket::stream<tcp::socket> ws(std::move(socket));
			ws.accept();

			cv::VideoCapture cap(1);  // Open the camera
			cv::Mat frame;

			while (true) {
				cap >> frame;

				// Convert OpenCV Mat to base64
				std::vector<uchar> buffer;
				cv::imencode(".jpg", frame, buffer);
				std::string base64_image = base64Encode(buffer);

				// Send the base64 encoded image over WebSocket
				try {
					ws.write(net::buffer(base64_image));
				}
				catch (const beast::system_error& e) {
					if (e.code() != websocket::error::closed) {
						std::cerr << "WebSocket write error: " << e.what() << std::endl;
					}
					break;  // Break the inner loop if WebSocket is closed
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}
		}
	}
	catch (const std::exception &e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return;
	}
}
void usingSecureWS() {
	net::io_context ioc;

	// Create and configure SSL context
	ssl::context ctx(ssl::context::tlsv12);
	ctx.use_certificate_chain_file("localhost_cert.crt"); // Replace with your certificate file
	ctx.use_private_key_file("localhost_cert.key", ssl::context::pem); // Replace with your private key file

	tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 8080));

	while (true) {
		tcp::socket socket(ioc);
		acceptor.accept(socket);

		// Wrap the socket with SSL
		ssl::stream<tcp::socket&> ssl_stream(socket, ctx);
		ssl_stream.handshake(ssl::stream_base::server);

		websocket::stream<ssl::stream<tcp::socket&>> ws(std::move(ssl_stream));
		ws.accept();

		cv::VideoCapture cap(1);  // Open the camera
		cv::Mat frame;

		while (true) {
			cap >> frame;

			// Convert OpenCV Mat to base64
			std::vector<uchar> buffer;
			cv::imencode(".jpg", frame, buffer);
			
			std::string base64_image = base64Encode(buffer);

			// Send the base64 encoded image over WebSocket
			try {
				ws.write(net::buffer(base64_image));
			}
			catch (const beast::system_error& e) {
				if (e.code() != websocket::error::closed) {
					std::cerr << "WebSocket write error: " << e.what() << std::endl;
				}
				break;  // Break the inner loop if WebSocket is closed
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
}

int main() {
	/*std::string camera{ "FHD Camera" };
	std::string vid{ "0380" };
	std::string pid{ "2006" };
	runCamerabyName(camera, vid, pid);*/
	//usingUnsecureWS();
	usingSecureWS();
	return 0;
}