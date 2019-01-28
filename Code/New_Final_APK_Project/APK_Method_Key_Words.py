
#用于将Intent关键字相关的内容保存下来
key_Intent=['Intent(','IntentFilter(']
# 1)Intent intent = new Intent(Intent_Demo1.this, Intent_Demo1_Result1.class);
#   startActivity(intent);

# 2)Intent intent = new Intent();
#   intent.setClass(Intent_Demo1.this, Intent_Demo1_Result1.class);
#   startActivity(intent);

# 3)Intent intent = new Intent();
#   intent.setClassName(Intent_Demo1.this, "com.great.activity_intent.Intent_Demo1_Result1");
#   startActivity(intent);

# 4) Intent intent = new Intent();
#    //setComponent's parameter:ComponentName
#    intent.setComponent(new ComponentName(Intent_Demo1.this, Intent_Demo1_Result1.class));
#    startActivity(intent);
#用于将这些函数保存下来，除了回调函数之外，这些函数也非常重要
key_registers=['addGpsStatusListener','requestLocationUpdates','registerListener',
            'registerComponentCallbacks','registerReceiver','setOnClickListener',
            'setOnTouchListener','setOnGenericMotionListener','setOnLongClickListener',
            'setOnDragListener','setOnFocusChangeListener','setOnCreateContextMenuListener'
               ,'unregisterComponentCallbacks','unregisterReceiver','removeUpdates'
               ,'unregisterListener','startActivity','startService','stopService'
               ,'bindService','unbindService','startActivities','setContentView','finish',
               'addCategory', 'addFlags', 'cloneFilter', 'clone', 'cloneFilter', 'createChooser',
               'describeContents', 'fillIn', 'filterEquals', 'filterHashCode', 'getAction', 'getBooleanArrayExtra',
               'getBooleanExtra', 'getBundleExtra', 'getByteArrayExtra', 'getByteExtra', 'getCategories',
               'getCharArrayExtra', 'getCharExtra', 'getCharSequenceArrayExtra', 'getClipData', 'getComponent',
               'putExtra','setClass', 'setClassName', 'setComponent', 'hasExtra', 'makeMainActivity', 'setData',
               'getStringExtra', 'addAction' ]
# amd_key_words=['android.telephony.TelephonyManager','getPackageManager','setComponentEnabledSetting',
#            'android.app.action.ADD_DEVICE_ADMIN','android.app.extra.DEVICE_ADMIN','android.app.admin.DevicePolicyManager',
#            'android.intent.action.BOOT_COMPLETED','android.intent.action.USER_PRESENT','android.net.ConnectivityManager',
#            'getActiveNetworkInfo','openConnection','java.net.HttpURLConnection','android.app.admin.DeviceAdminReceiver',
#            'android.intent.action.DELETE','android.provider.ContactsContract$CommonDataKinds$Phone.CONTENT_URI',
#            'android.net.Uri.parse','android.intent.extra.PHONE_NUMBER','android.provider.Telephony.SMS_RECEIVED',
#            'android.intent.action.NEW_OUTGOING_CALL','android.intent.action.CALL','getSystemService("phone")'
#            ,'getDeviceId','getSubscriberId','getSimSerialNumber','android.telephony.SmsManager',
#            'getLine1Number','android.net.Uri.fromParts','android.webkit.WebViewgetSimCountryIso','getApplicationInfo','setDataAndType',
#            'application/vnd.android.package-archive','getNetworkInfo','android.telephony.SmsMessage.createFromPdu',
#            'android.intent.action.PHONE_STATE','android.telephony.TelephonyManager.EXTRA_STATE_RINGING','android.app.AlarmManager',
#            'android.hardware.Camera.open','startPreview','takePicture','android.telephony.TelephonyManager.EXTRA_STATE_IDLE',
#            'android.telephony.TelephonyManager.EXTRA_STATE_OFFHOOK','getNetworkCountryIso','getNetworkOperatorName',
#            'getSimCountryIso','getSimOperatorName','android.location.LocationManager','getSystemService("location")',
#            'requestLocationUpdates','removeUpdates','onPictureTaken','android.hardware.Camera','takePicture','setPreviewDisplay',
#            'startPreview','android.net.wifi.WifiManager','android.net.wifi.WifiInfo','getConnectionInfo','getSystemService("wifi")',
#            'android.net.conn.CONNECTIVITY_CHANGE','getSystemService("connectivity")','android.net.NetworkInfo$State',
#            'getSystemService("alarm")','android.intent.action.PACKAGE_ADDED','getLaunchIntentForPackage',
#            'getParcelableExtra("networkInfo")','android.os.Build$VERSION.SDK_INT','android.os.Build$VERSION.RELEASE',
#            'android.media.AudioRecord','android.media.AudioRecord$OnRecordPositionUpdateListener','android.media.AudioRecord.getMinBufferSize',
#            'setPositionNotificationPeriod','setRecordPositionUpdateListener','startRecording','android.provider.CallLog$Calls.CONTENT_URI',
#            'android.provider.ContactsContract$Contacts.CONTENT_URI','android.os.Environment.getExternalStorageDirectory','android.location.LocationListener',
#            'android.hardware.Camera$PictureCallback','getSystemService("activity")','android.app.ActivityManager$RunningTaskInfo','com.android.locker.MainActivity$mainActivity.Activity.finishActivity',
#            'android.telephony.SmsManager.getDefault','android.intent.action.CALL','getSimOperator','sendTextMessage','JSONObject',
#            'application/vnd.android.package-archive']
amd_key_words=['android.telephony.TelephonyManager',
           'android.app.action.ADD_DEVICE_ADMIN','android.app.extra.DEVICE_ADMIN','android.app.admin.DevicePolicyManager',
           'android.intent.action.BOOT_COMPLETED','android.intent.action.USER_PRESENT','android.net.ConnectivityManager',
           'getActiveNetworkInfo','openConnection','java.net.HttpURLConnection','android.app.admin.DeviceAdminReceiver',
           'android.intent.action.DELETE','android.provider.ContactsContract$CommonDataKinds$Phone.CONTENT_URI',
           'android.intent.extra.PHONE_NUMBER','android.provider.Telephony.SMS_RECEIVED',
           'android.intent.action.NEW_OUTGOING_CALL','android.intent.action.CALL','getSystemService("phone")'
           ,'getDeviceId','getSubscriberId','getSimSerialNumber','android.telephony.SmsManager',
           'getLine1Number','android.net.Uri.fromParts','android.webkit.WebViewgetSimCountryIso',
           'application/vnd.android.package-archive','android.telephony.SmsMessage.createFromPdu',
           'android.intent.action.PHONE_STATE','android.telephony.TelephonyManager.EXTRA_STATE_RINGING',
           'android.hardware.Camera.open','takePicture','android.telephony.TelephonyManager.EXTRA_STATE_IDLE',
           'android.telephony.TelephonyManager.EXTRA_STATE_OFFHOOK','getNetworkCountryIso','getNetworkOperatorName',
           'getSimCountryIso','getSimOperatorName','android.location.LocationManager','getSystemService("location")',
           'requestLocationUpdates','onPictureTaken','android.hardware.Camera','takePicture',
           'android.net.wifi.WifiManager','android.net.wifi.WifiInfo','getSystemService("wifi")',
           'android.net.conn.CONNECTIVITY_CHANGE','getSystemService("connectivity")',
           'android.intent.action.PACKAGE_ADDED','getLaunchIntentForPackage',
           'getParcelableExtra("networkInfo")','android.os.Build$VERSION.SDK_INT','android.os.Build$VERSION.RELEASE',
           'android.media.AudioRecord$OnRecordPositionUpdateListener','android.media.AudioRecord.getMinBufferSize',
           'android.provider.CallLog$Calls.CONTENT_URI',
           'android.provider.ContactsContract$Contacts.CONTENT_URI','android.os.Environment.getExternalStorageDirectory','android.location.LocationListener',
           'android.hardware.Camera$PictureCallback','android.app.ActivityManager$RunningTaskInfo','com.android.locker.MainActivity$mainActivity.Activity.finishActivity',
           'android.telephony.SmsManager.getDefault','android.intent.action.CALL','JSONObject',
           'application/vnd.android.package-archive']