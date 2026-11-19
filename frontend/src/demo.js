// ملفات ميزات تجريبية تُرسل إلى POST /predict/features لتجربة الواجهة بدون ملف APK.
// الأسماء من أعمدة Final_Balanced_Three_Datasets.csv (أذونات Android فقط).
export const DEMOS = {
  malware: {
    title: "تطبيق مشبوه (SMS + معرّف الجهاز)",
    features: {
      SEND_SMS: 1, RECEIVE_SMS: 1, READ_SMS: 1, WRITE_SMS: 1, READ_PHONE_STATE: 1, INTERNET: 1,
      RECEIVE_BOOT_COMPLETED: 1, READ_CONTACTS: 1, CALL_PHONE: 1, GET_TASKS: 1, INSTALL_PACKAGES: 1,
    },
  },
  benign: {
    title: "تطبيق اعتيادي (شبكة + إشعارات)",
    features: {
      INTERNET: 1, ACCESS_NETWORK_STATE: 1, WAKE_LOCK: 1, VIBRATE: 1,
    },
  },
};
