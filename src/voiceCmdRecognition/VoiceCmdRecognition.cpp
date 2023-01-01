/*******************************************************************************
 *
 * Filename:
 * ---------
 * VoiceCmdRecognition.cpp
 *
 * Project:
 * --------
 *   Android
 *
 * Description:
 * ------------
 *   This file implements the  handling about voice recognition features.
 *
 * Author:
 * -------
 *   Donglei Ji (mtk80823)
 *
 *------------------------------------------------------------------------------
 *******************************************************************************/

/*=============================================================================
 *                              Include Files
 *===========================================================================*/
#include <cutils/log.h>
#include <utils/Errors.h>
#include <cutils/properties.h>
#include <cutils/bitops.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <utils/threads.h>

// For get project config
#include "AudioParamParser.h"

#include "VoiceCmdRecognition.h"
#define MTK_LOG_ENABLE 1
#include "AudioToolkit.h"
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "VoiceCommandRecognition"

#define SAMPLES_LIB (160)  // 10ms for 16k sample rate and 1 channel
#define MAX_SAMPLE_LENGTH (SAMPLES_LIB * 300)  // 10ms * 200 = 2sec

#define kWaitingTimeOutMS (3000) // for wiat lock time out

#if VOW_PHASE25_SUPPORT
#define VOW_P25_UBM_PATH "/vendor/etc/vowphase25/training/ubmfile/"
#define VOW_P25_PATTERN_PATH "/sdcard/"
#define VOW_P25_DEBUG_PATH "/sdcard/"
#endif
#if VOW_SID_SUPPORT
#define VOW_P23_UBM_PATH "/vendor/etc/vowphase23/training/ubmfile/"
#define VOW_P23_PATTERN_PATH "/sdcard/0_vp23.dat"
#endif

#define MTK_VOW_ENABLE_CPU_BOOST

#if defined(MTK_VOW_ENABLE_CPU_BOOST)
// Power HAL
#include <vendor/mediatek/hardware/mtkpower/1.0/IMtkPerf.h>
#include "mtkperf_resource.h"
using std::vector;
using ::android::hardware::hidl_vec;
using namespace vendor::mediatek::hardware::mtkpower::V1_0;
#define CPU_BOOST_TIME_OUT (15 * 1000) //ms
#endif

// vow engine lib path
#if defined(__LP64__)
#define VOW_ENGINE_LIBRARY_PATH "/system/lib64"
#else
#define VOW_ENGINE_LIBRARY_PATH "/system/lib"
#endif
#define VOW_ENGINE_LIBRARY_NAME "libvow_ap_train"

// vow engine feature XML
#define XML_ENGINE_FEATURE_AUDIOTYPE_NAME "VoWEngineFeature"

struct VowEngine {
    void *handle;
    _VOWE_Trainer_init init;
    _VOWE_Trainer_pushToTalk pushToTalk;
    _VOWE_Trainer_inputSignal inputSignal;
    _VOWE_Trainer_diagnose diagnose;
    _VOWE_Trainer_getCurUtterance getCurUtterance;
    _VOWE_Trainer_enroll enroll;
    _VOWE_Trainer_release release;
    _VOWE_Trainer_version version;
    _VOWE_Trainer_setArg setArg;
    _VOWE_Trainer_getArg getArg;
    _VOWE_Trainer_backgroundUpdate backgroundUpdate;
};
static struct VowEngine gVowEngine;

using namespace android;

static __inline short ClipToShort(int x)
{
    int sign;

    /* clip to [-32768, 32767] */
    sign = x >> 31;
    if (sign != (x >> 15))
    x = sign ^ ((1 << 15) - 1);

    return (short)x;
}

String8 PrintEncodedString(String8 strKey, size_t len, void *ptr)
{
    String8 returnValue = String8("");
    size_t sz_Needed;
    size_t sz_enc;
    char *buf_enc = NULL;
    bool bPrint = false;

    //ALOGD("%s in, len = %d", __FUNCTION__, len);
    sz_Needed = Base64_OutputSize(true, len);
    buf_enc = new char[sz_Needed + 1];
    buf_enc[sz_Needed] = 0;

    sz_enc = Base64_Encode((unsigned char *)ptr, buf_enc, len);

    if (sz_enc != sz_Needed) {
        ALOGE("%s(), Encode Error!!!after encode (%s), len(%d), sz_Needed(%d), sz_enc(%d)",
            __FUNCTION__, buf_enc, (int)len, (int)sz_Needed, (int)sz_enc);
    } else {
        bPrint = true;
        //ALOGD("%s(), after encode (%s), len(%d), sz_enc(%d)", __FUNCTION__, buf_enc, len, sz_enc);
    }

    if (bPrint) {
        String8 StrVal = String8(buf_enc, sz_enc);
        returnValue += strKey;
        returnValue += StrVal;
        //returnValue += String8(";");
    }

    if (buf_enc != NULL) {
        delete[] buf_enc;
    }

    return returnValue;
}
/*
static status_t GetDecodedData(String8 strPara, size_t len, void *ptr)
{
    size_t sz_in = strPara.size();
    size_t sz_needed = Base64_OutputSize(false, sz_in);
    size_t sz_dec;
    status_t ret = NO_ERROR;

    if (sz_in <= 0) {
        return NO_ERROR;
    }

    //ALOGD("%s in, len = %d", __FUNCTION__, len);
    unsigned char *buf_dec = new unsigned char[sz_needed];
    sz_dec = Base64_Decode(strPara.string(), buf_dec, sz_in);

    if (sz_dec > sz_needed || sz_dec <= sz_needed - 3) {
        ALOGE("%s(), Decode Error!!!after decode (%s), sz_in(%d), sz_needed(%d), sz_dec(%d)",
            __FUNCTION__, buf_dec, (int)sz_in, (int)sz_needed, (int)sz_dec);
    } else {
        // sz_needed-3 < sz_dec <= sz_needed
        //ALOGD("%s(), after decode, sz_in(%d), sz_dec(%d) len(%d) sizeof(ret)=%d",
        //    __FUNCTION__, sz_in, sz_dec, len, sizeof(ret));
        //print_hex_buffer (sz_dec, buf_dec);
    }

    if ((len == 0) || (len == sz_dec-sizeof(ret))) {
       if (len) {
           ret = (status_t)*(buf_dec);
           unsigned char *buff = (buf_dec + 4);
           memcpy(ptr, buff, len);
       } else {
          const char * IntPtr = (char *)buf_dec;
          ret = atoi(IntPtr);
          //ALOGD("%s len = 0 ret(%d)", __FUNCTION__, ret);
       }
    } else {
       ALOGD("%s decoded buffer isn't right format", __FUNCTION__);
    }

    if (buf_dec != NULL) {
        delete[] buf_dec;
    }

    return ret;
}

status_t GetAudioData(int par1, size_t len, void *ptr)
{
    static String8 keyGetBuffer = String8("GetBuffer=");
    int iPara[2];
    iPara[0] = par1;
    iPara[1] = len;

    String8 strPara = PrintEncodedString(keyGetBuffer, sizeof(iPara), iPara);
    String8 returnValue = AudioSystem::getParameters(0, strPara);

    String8 newval; //remove "GetBuffer="
    newval.appendFormat("%s", returnValue.string() + keyGetBuffer.size());

    return GetDecodedData(newval, len, ptr);
}

bool is_tablet_library()
{
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.vendor.mtk_is_tablet", value, "0");
    int bflag=atoi(value);
    ALOGD("is_tablet_library:%d", bflag);

    return ((bflag == 1)?true:false);
}
*/

uint32_t ring_buffer_get_data_byte_count(struct ring_buffer_information *p_info)
{
    uint32_t buffer_byte_count = p_info->buffer_byte_count;
    uint32_t write_pointer     = p_info->write_pointer;
    uint32_t read_pointer      = p_info->read_pointer;
    uint32_t data_byte_count;
    if (write_pointer >= read_pointer) {
        data_byte_count = write_pointer - read_pointer;
    } else {
        data_byte_count = (buffer_byte_count << 1) - read_pointer + write_pointer;
    }
    return data_byte_count;
}

uint32_t ring_buffer_get_space_byte_count(struct ring_buffer_information *p_info)
{
    return p_info->buffer_byte_count - ring_buffer_get_data_byte_count(p_info);
}

void ring_buffer_get_write_information(struct ring_buffer_information *p_info, uint8_t **pp_buffer, uint32_t *p_byte_count)
{
    uint32_t buffer_byte_count = p_info->buffer_byte_count;
    uint32_t space_byte_count  = ring_buffer_get_space_byte_count(p_info);
    uint8_t *buffer_pointer    = p_info->buffer_base_pointer;
    uint32_t write_pointer     = p_info->write_pointer;
    uint32_t tail_byte_count;
    if (write_pointer < buffer_byte_count) {
        *pp_buffer = buffer_pointer + write_pointer;
        tail_byte_count = buffer_byte_count - write_pointer;
    } else {
        *pp_buffer = buffer_pointer + write_pointer - buffer_byte_count;
        tail_byte_count = (buffer_byte_count << 1) - write_pointer;
    }
    *p_byte_count = MINIMUM(space_byte_count, tail_byte_count);
    return;
}

void ring_buffer_get_read_information(struct ring_buffer_information *p_info, uint8_t **pp_buffer, uint32_t *p_byte_count)
{
    uint32_t buffer_byte_count = p_info->buffer_byte_count;
    uint32_t data_byte_count   = ring_buffer_get_data_byte_count(p_info);
    uint8_t *buffer_pointer    = p_info->buffer_base_pointer;
    uint32_t read_pointer      = p_info->read_pointer;
    uint32_t tail_byte_count;
    if (read_pointer < buffer_byte_count) {
        *pp_buffer = buffer_pointer + read_pointer;
        tail_byte_count = buffer_byte_count - read_pointer;
    } else {
        *pp_buffer = buffer_pointer + read_pointer - buffer_byte_count;
        tail_byte_count = (buffer_byte_count << 1) - read_pointer;
    }
    *p_byte_count = MINIMUM(data_byte_count, tail_byte_count);
    return;
}

void ring_buffer_write_done(struct ring_buffer_information *p_info, uint32_t write_byte_count)
{
    uint32_t buffer_byte_count = p_info->buffer_byte_count;
    uint32_t buffer_end        = buffer_byte_count << 1;
    uint32_t write_pointer     = p_info->write_pointer + write_byte_count;
    p_info->write_pointer = write_pointer >= buffer_end ? write_pointer - buffer_end : write_pointer;
    return;
}

void ring_buffer_read_done(struct ring_buffer_information *p_info, uint32_t read_byte_count)
{
    uint32_t buffer_byte_count = p_info->buffer_byte_count;
    uint32_t buffer_end        = buffer_byte_count << 1;
    uint32_t read_pointer      = p_info->read_pointer + read_byte_count;
    p_info->read_pointer = read_pointer >= buffer_end ? read_pointer - buffer_end : read_pointer;
    return;
}

static bool isFileExist(const char *filename) {
    bool ret = false;
    if (FILE *file = fopen(filename, "r")) {
        if (fclose(file)) {
            ALOGE("%s(), fclose fail!", __func__);
        }
        ret = true;
    }
    ALOGD("%s(), is file exist = %d, file = %s", __FUNCTION__, ret, filename);
    return ret;
}

static String8 getEnginePostfix(void) {
    String8 postfix = String8("");

    // init AppHandle
    AppOps *appOps = appOpsGetInstance();
    if (appOps == NULL) {
        ALOGE("Error %s %d", __FUNCTION__, __LINE__);
        return postfix;
    }

    // get parameter engine feature
    char audioTypeName[] = XML_ENGINE_FEATURE_AUDIOTYPE_NAME;  // define xml names
    std::string paramCommonPath = "VoWEngineFeature,common";
    char *result = appOps->utilNativeGetParam(audioTypeName, paramCommonPath.c_str(), "training");
    if (!result) {
        ALOGE("%s(), get paramUnit fail, paramPath = %s, use common",
                __FUNCTION__,
                paramCommonPath.c_str());
        return postfix;
    }
    postfix = String8(result);
    free(result);
    ALOGD("%s(), postfix = %s", __FUNCTION__, postfix.string());

    return postfix;
}

static status_t openVowEngine(void) {
    char path[PATH_MAX] = "";
    int ret = 0;
    String8 postfix = getEnginePostfix();
    if (postfix.length() > 0){
        ret = snprintf(path, sizeof(path), "%s/%s_%s.so",
                VOW_ENGINE_LIBRARY_PATH, VOW_ENGINE_LIBRARY_NAME, postfix.string());
    } else if (postfix.length() == 0) {
        ret = snprintf(path, sizeof(path), "%s/%s.so",
                VOW_ENGINE_LIBRARY_PATH, VOW_ENGINE_LIBRARY_NAME);
    }
    if (access(path, R_OK) != 0) {
        ALOGE("%s(), path = %s is incorrect!", __FUNCTION__, path);
        return BAD_VALUE;
    }
    ALOGD("%s(), Load path = %s", __FUNCTION__, path);
    gVowEngine.handle = dlopen(path, RTLD_NOW);
    const char *dlsym_error1 = dlerror();
    ALOGE("%s(), dlerror() = %s", __FUNCTION__, dlsym_error1);
    if (gVowEngine.handle == NULL) {
        ALOGE("%s(), -DL open vow_engine_handle path [%s] fail", __FUNCTION__, path);
        return BAD_VALUE;
    } else {
        int dlsym_ret = 0;

        // VOWE_Trainer_init
        gVowEngine.init = (_VOWE_Trainer_init)dlsym(gVowEngine.handle, "VOWE_Trainer_init");
        ALOGV("%s(), gVowEngine.init = %p", __FUNCTION__, gVowEngine.init);
        if (gVowEngine.init == NULL) {
            ALOGE("%s(), -dlsym VOWE_Trainer_init fail", __FUNCTION__);
            dlsym_ret = BAD_VALUE;
        }

        // VOWE_Trainer_pushToTalk
        gVowEngine.pushToTalk = (_VOWE_Trainer_pushToTalk)dlsym(gVowEngine.handle, "VOWE_Trainer_pushToTalk");
        ALOGV("%s(), gVowEngine.pushToTalk = %p", __FUNCTION__, gVowEngine.pushToTalk);
        if (gVowEngine.pushToTalk == NULL) {
            ALOGE("%s(), -dlsym VOWE_Trainer_pushToTalk fail", __FUNCTION__);
            dlsym_ret = BAD_VALUE;
        }

        // VOWE_Trainer_inputSignal
        gVowEngine.inputSignal = (_VOWE_Trainer_inputSignal)dlsym(gVowEngine.handle, "VOWE_Trainer_inputSignal");
        ALOGV("%s(), gVowEngine.inputSignal = %p", __FUNCTION__, gVowEngine.inputSignal);
        if (gVowEngine.inputSignal == NULL) {
            ALOGE("%s(), -dlsym VOWE_Trainer_inputSignal fail", __FUNCTION__);
            dlsym_ret = BAD_VALUE;
        }

        // VOWE_Trainer_diagnose
        gVowEngine.diagnose = (_VOWE_Trainer_diagnose)dlsym(gVowEngine.handle, "VOWE_Trainer_diagnose");
        ALOGV("%s(), gVowEngine.diagnose = %p", __FUNCTION__, gVowEngine.diagnose);
        if (gVowEngine.diagnose == NULL) {
            ALOGE("%s(), -dlsym VOWE_Trainer_diagnose fail", __FUNCTION__);
            dlsym_ret = BAD_VALUE;
        }

        // VOWE_Trainer_getCurUtterance
        gVowEngine.getCurUtterance = (_VOWE_Trainer_getCurUtterance)dlsym(gVowEngine.handle, "VOWE_Trainer_getCurUtterance");
        ALOGV("%s(), gVowEngine.getCurUtterance = %p", __FUNCTION__, gVowEngine.getCurUtterance);
        if (gVowEngine.getCurUtterance == NULL) {
            ALOGE("%s(), -dlsym VOWE_Trainer_getCurUtterance fail", __FUNCTION__);
            dlsym_ret = BAD_VALUE;
        }

        // VOWE_Trainer_enroll
        gVowEngine.enroll = (_VOWE_Trainer_enroll)dlsym(gVowEngine.handle, "VOWE_Trainer_enroll");
        ALOGV("%s(), gVowEngine.enroll = %p", __FUNCTION__, gVowEngine.enroll);
        if (gVowEngine.enroll == NULL) {
            ALOGE("%s(), -dlsym VOWE_Trainer_enroll fail", __FUNCTION__);
            dlsym_ret = BAD_VALUE;
        }

        // VOWE_Trainer_release
        gVowEngine.release = (_VOWE_Trainer_release)dlsym(gVowEngine.handle, "VOWE_Trainer_release");
        ALOGV("%s(), gVowEngine.release = %p", __FUNCTION__, gVowEngine.release);
        if (gVowEngine.release == NULL) {
            ALOGE("%s(), -dlsym VOWE_Trainer_release fail", __FUNCTION__);
            dlsym_ret = BAD_VALUE;
        }

        // VOWE_Trainer_version
        gVowEngine.version = (_VOWE_Trainer_version)dlsym(gVowEngine.handle, "VOWE_Trainer_version");
        ALOGV("%s(), gVowEngine.version = %p", __FUNCTION__, gVowEngine.version);
        if (gVowEngine.version == NULL) {
            ALOGE("%s(), -dlsym VOWE_Trainer_version fail", __FUNCTION__);
            dlsym_ret = BAD_VALUE;
        }

        // VOWE_Trainer_setArg
        gVowEngine.setArg = (_VOWE_Trainer_setArg)dlsym(gVowEngine.handle, "VOWE_Trainer_setArg");
        ALOGV("%s(), gVowEngine.setArg = %p", __FUNCTION__, gVowEngine.setArg);
        if (gVowEngine.setArg == NULL) {
            ALOGE("%s(), -dlsym VOWE_Trainer_setArg fail", __FUNCTION__);
            dlsym_ret = BAD_VALUE;
        }

        // VOWE_Trainer_getArg
        gVowEngine.getArg = (_VOWE_Trainer_getArg)dlsym(gVowEngine.handle, "VOWE_Trainer_getArg");
        ALOGV("%s(), gVowEngine.getArg = %p", __FUNCTION__, gVowEngine.getArg);
        if (gVowEngine.getArg == NULL) {
            ALOGE("%s(), -dlsym VOWE_Trainer_getArg fail", __FUNCTION__);
            dlsym_ret = BAD_VALUE;
        }

        // VOWE_Trainer_backgroundUpdate
        gVowEngine.backgroundUpdate = (_VOWE_Trainer_backgroundUpdate)dlsym(gVowEngine.handle, "VOWE_Trainer_backgroundUpdate");
        ALOGV("%s(), gVowEngine.backgroundUpdate = %p", __FUNCTION__, gVowEngine.backgroundUpdate);
        if (gVowEngine.backgroundUpdate == NULL) {
            ALOGE("%s(), -dlsym VOWE_Trainer_backgroundUpdate fail", __FUNCTION__);
            dlsym_ret = BAD_VALUE;
        }

        if (dlsym_ret != 0) {
            ALOGE("%s(), dlopen fail!", __FUNCTION__);
            dlclose(gVowEngine.handle);
            memset((void *)&gVowEngine, 0, sizeof(gVowEngine));
            return BAD_VALUE;
        }
        ALOGD("%s(), dlopen success", __FUNCTION__);
    }
    return OK;
}

static void closeVowEngine(void) {
    if (gVowEngine.handle != NULL) {
        dlclose(gVowEngine.handle);
        memset((void *)&gVowEngine, 0, sizeof(gVowEngine));
    }
}

static void *enrollTrainingThread(void *pParam)
{
    // voice data is enough, start to training voice password
    unsigned int quailty_score;
    VoiceCmdRecognition *pVoiceRecogize = (VoiceCmdRecognition *)pParam;

    /*
    * Adjust thread priority
    */
    prctl(PR_SET_NAME, (unsigned long)"enroll Training Thread", 0, 0, 0);
    setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_AUDIO);
    ALOGD("%s(), pid: %d, tid: %d", __FUNCTION__, getpid(), gettid());

    pVoiceRecogize->m_enrolling = true;
    if (gVowEngine.enroll != NULL) {
        if (gVowEngine.enroll(pVoiceRecogize->m_PatternFd) == vowe_bad) {
            ALOGW("TrainingEnroll failed!");
            quailty_score = 0;
        } else {
            quailty_score = 100;

            // copy training_ul.pcm to retrain.pcm
            // training_ul.pcm is closed in stopCaptureVoice, so is can be opened and copied after enroll is done
            pVoiceRecogize->saveRetrainPcm();

            // get training utterance for UI playback
            int ret = 0;
            int sampleNumber = 0;
            short *pcmBuffer = NULL;
            if (gVowEngine.getCurUtterance != NULL) {
                ret = gVowEngine.getCurUtterance(&pcmBuffer, &sampleNumber);
                if (sampleNumber <= 0) {
                    ALOGE("%s(), sampleNumber <= 0! no training utterance", __FUNCTION__);
                } else if (pcmBuffer == NULL) {
                    ALOGE("%s(), pcmBuffer == NULL! no training utterance", __FUNCTION__);
                } else if (ret != vowe_ok) {
                    ALOGE("%s(), VOWE_Trainer_getCurUtterance error! no training utterance", __FUNCTION__);
                } else {
                    pVoiceRecogize->writeWavFile(pcmBuffer, sampleNumber);
                }
            }
        }
    } else {
        ALOGE("%s(), load enroll failed!", __FUNCTION__);
        quailty_score = 0;
    }
    ALOGD("%s, call Release", __FUNCTION__);
    pVoiceRecogize->voiceRecognitionRelease(VOICE_PW_TRAINING_MODE);

    pVoiceRecogize->notify(VOICE_TRAINING_FINISH, quailty_score, 0);

    pVoiceRecogize->m_enrolling = false;

    pthread_exit(NULL);
    return 0;
}

static void *captureVoiceLoop(void *pParam)
{
    ALOGD("capture voice thread in +");
    int size = 0;
    int free_size = 0;
    bool drop = false;
    VoiceCmdRecognition *pVoiceRecogize = (VoiceCmdRecognition *)pParam;

    /*
    * Adjust thread priority
    */
    prctl(PR_SET_NAME, (unsigned long)"capture Voice Loop", 0, 0, 0);
    setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_AUDIO);
    ALOGD("%s(), pid: %d, tid: %d", __FUNCTION__, getpid(), gettid());

    pVoiceRecogize->setCaptureThreadStarted(true);

    while (pVoiceRecogize->m_bStarted) {
        if (pVoiceRecogize->m_pAudioStream != 0) {
            size = BUF_READ_SIZE;
            pthread_mutex_lock(&pVoiceRecogize->m_BufMutex);
            free_size = ring_buffer_get_space_byte_count(&pVoiceRecogize->m_rb_info1) / sizeof(short);

            drop = false;
            if (free_size < size) {
                // buffer overflow
                ALOGD("%s(), voice buffer overflow!, size=%d, free_size=%d", __func__, size, free_size);
                drop = true;
            }
            pthread_mutex_unlock(&pVoiceRecogize->m_BufMutex);
            if (drop == false) {
                short *p_buf_1 = NULL;
                short *p_buf_2 = NULL;
                uint32_t buf_size_1 = 0;
                uint32_t buf_size_2 = 0;
                pthread_mutex_lock(&pVoiceRecogize->m_BufMutex);
                ring_buffer_get_write_information(&pVoiceRecogize->m_rb_info1, (uint8_t **)&p_buf_1, &buf_size_1);
                ring_buffer_get_write_information(&pVoiceRecogize->m_rb_info2, (uint8_t **)&p_buf_2, &buf_size_2);
                pthread_mutex_unlock(&pVoiceRecogize->m_BufMutex);
                if (pVoiceRecogize->m_pAudioStream->readPCM(
                        p_buf_1,
                        p_buf_2,
                        0,
                        size) != OK) {
                    ALOGD("%s(), readPCM error!!", __func__);
                    break;
                }
                pthread_mutex_lock(&pVoiceRecogize->m_BufMutex);
                ring_buffer_write_done(&pVoiceRecogize->m_rb_info1, size * sizeof(short));
                ring_buffer_write_done(&pVoiceRecogize->m_rb_info2, size * sizeof(short));
                pthread_mutex_unlock(&pVoiceRecogize->m_BufMutex);
                pVoiceRecogize->m_already_read = true;
            } else {
                ALOGI("%s(), force drop!", __func__);
            }
        }
    }

    pVoiceRecogize->setCaptureThreadStarted(false);

    ALOGD("capture voice thread out -");
    pthread_exit(NULL);
    return 0;
}

static int GOOD_UTTERANCE_NUMBER = 1;
static void *TrainingVoiceLoop(void *pParam)
{
    ALOGD("Training voice thread in +");

    GOOD_UTTERANCE_NUMBER = 1;

    VoiceCmdRecognition *pVoiceRecogize = (VoiceCmdRecognition *)pParam;
    bool bFirstFrame = true;
    int size = 0;
    int confidence = 0;
    int msg = vowe_next_frame;
    int notify_back = -1;
    float snr_value = 0;
    char *pRtnContactNameArray[2];
    int reserv_size = 0;
    int left_size = 0;
    short *pULBuf1;
    short *pULBuf2;
    short *pULBuf1_temp = new short[SAMPLES_LIB];
    short *pULBuf2_temp = new short[SAMPLES_LIB];

    /*
    * Adjust thread priority
    */
    prctl(PR_SET_NAME, (unsigned long)"Training Voice Loop", 0, 0, 0);
    setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_AUDIO + 1);
    ALOGD("%s(), pid: %d, tid: %d", __FUNCTION__, getpid(), gettid());

    memset(pULBuf1_temp, 0, SAMPLES_LIB * sizeof(short));
    memset(pULBuf2_temp, 0, SAMPLES_LIB * sizeof(short));
    memset(pRtnContactNameArray, 0, 2 * sizeof(char *));
    ALOGV("pVoiceRecogize->recordLockSignal()");
    pVoiceRecogize->recordLockSignal();

    pVoiceRecogize->setTrainingThreadStarted(true);

    while (pVoiceRecogize->m_bStarted) {
        // reset msg
        msg = vowe_next_frame;

        if (popcount(pVoiceRecogize->m_RecognitionMode) == 0) {
            usleep(5000);
        }
        // to capture valid voice data
        while ((msg == vowe_next_frame || msg == vowe_not_recording) &&
                popcount(pVoiceRecogize->m_RecognitionMode)) {
            if (pVoiceRecogize->m_pAudioStream != 0) {
                if (pVoiceRecogize->m_already_read) {
                    pthread_mutex_lock(&pVoiceRecogize->m_BufMutex);
                    reserv_size = ring_buffer_get_data_byte_count(&pVoiceRecogize->m_rb_info1) / sizeof(short);
                    pthread_mutex_unlock(&pVoiceRecogize->m_BufMutex);
                } else {
                    reserv_size = 0;
                    ALOGV("reserv_size = 0");
                }
                size = SAMPLES_LIB;
                if (reserv_size >= size) {
                    uint8_t *p_buf_1 = NULL;
                    uint8_t *p_buf_2 = NULL;
                    uint32_t buf_size_1 = 0;
                    uint32_t buf_size_2 = 0;
                    if (bFirstFrame == true) {
                        ALOGD("start receiving data");
                        bFirstFrame = false;
                    }

                    ring_buffer_get_read_information(&pVoiceRecogize->m_rb_info1, &p_buf_1, &buf_size_1);
                    ring_buffer_get_read_information(&pVoiceRecogize->m_rb_info2, &p_buf_2, &buf_size_2);
                    left_size = buf_size_1 / sizeof(short);
                    if (left_size < size) {
                        memcpy(&pULBuf1_temp[0], p_buf_1, left_size * sizeof(short));
                        memcpy(&pULBuf2_temp[0], p_buf_2, left_size * sizeof(short));
                        ring_buffer_read_done(&pVoiceRecogize->m_rb_info1, left_size * sizeof(short));
                        ring_buffer_read_done(&pVoiceRecogize->m_rb_info2, left_size * sizeof(short));
                        ring_buffer_get_read_information(&pVoiceRecogize->m_rb_info1, &p_buf_1, &buf_size_1);
                        ring_buffer_get_read_information(&pVoiceRecogize->m_rb_info2, &p_buf_2, &buf_size_2);
                        memcpy(&pULBuf1_temp[left_size], p_buf_1, (size - left_size) * sizeof(short));
                        memcpy(&pULBuf2_temp[left_size], p_buf_2, (size - left_size) * sizeof(short));
                        ring_buffer_read_done(&pVoiceRecogize->m_rb_info1, (size - left_size) * sizeof(short));
                        ring_buffer_read_done(&pVoiceRecogize->m_rb_info2, (size - left_size) * sizeof(short));
                    } else {
                        memcpy(&pULBuf1_temp[0], p_buf_1, size * sizeof(short));
                        memcpy(&pULBuf2_temp[0], p_buf_2, size * sizeof(short));
                        ring_buffer_read_done(&pVoiceRecogize->m_rb_info1, size * sizeof(short));
                        ring_buffer_read_done(&pVoiceRecogize->m_rb_info2, size * sizeof(short));
                    }
                    pULBuf1 = &pULBuf1_temp[0];
                    pULBuf2 = &pULBuf2_temp[0];

                    if (pVoiceRecogize->m_RecognitionMode & VOICE_PW_TRAINING_MODE) {
                        ALOGV("endPointDetection before");
                        if ((confidence != 100) &&
                            (pVoiceRecogize->m_ContinueVoiceTraining == true) &&
                            ((pVoiceRecogize->m_CaptureVoicePause == false) ||
                             (pVoiceRecogize->m_bStartRecordBackroundVoice == true))) {
                            //ALOGD("size = %d", size);
                            if (gVowEngine.inputSignal == NULL) {
                                ALOGE("%s(), load inputSignal fail!!", __FUNCTION__);
                                break;
                            }
                            if (gVowEngine.inputSignal(0, pULBuf1, size) == vowe_bad) {
                                ALOGD("Training VOWE_Trainer_inputSignal error!!");
                                break;
                            }
                            if (gVowEngine.diagnose == NULL) {
                                ALOGE("%s(), load diagnose fail!!", __FUNCTION__);
                                break;
                            }
                            msg = gVowEngine.diagnose(&confidence);
                            ALOGV("[dato]msg = %d, confidence = %d", msg, confidence);
                            if (msg != vowe_not_recording) {
                                pVoiceRecogize->m_pAudioStream->dumpAudioData(pULBuf1, pULBuf2, size << 1);
                            } else {
                                ALOGE("[err] VOWE_NOT_recordingconfidence = %d", confidence);
                            }
                        }
                    }

                    // background voice receiving
                    if (pVoiceRecogize->m_bStartRecordBackroundVoice == true) {
                        if (pVoiceRecogize->m_BackroundVoiceCount >= BACKGROUND_RECORD_SAMPLE_CNT) {
                            ALOGD("Background Voice receving done");
                            if (pVoiceRecogize->m_onStartProcessing == false) {
                                pVoiceRecogize->notify(VOICE_TRAINING_PROCESS, VOICE_ON_START_PROCESS, 0);
                                pVoiceRecogize->m_onStartProcessing = true;
                            }
                            pVoiceRecogize->m_bStartRecordBackroundVoice = false;
                            pVoiceRecogize->m_BackroundVoiceCount = 0;
                        } else {
                            ALOGV("Background cnt = %d", pVoiceRecogize->m_BackroundVoiceCount);
                            pVoiceRecogize->m_BackroundVoiceCount++;
                        }
                    }
                } else {
                    ALOGV("reserv_size(%d)", reserv_size);
                    usleep(3000);  // sleep 3ms
                }
            } else {
                break;
            }
        }

        // for voice password taining mode
        if ((pVoiceRecogize->m_bStartRecordBackroundVoice == false) &&
            (msg != vowe_next_frame) &&
            (pVoiceRecogize->m_RecognitionMode & VOICE_PW_TRAINING_MODE)) {

            pVoiceRecogize->m_bNeedToWait = false;
            pVoiceRecogize->m_bNeedToRelease = true;
            pVoiceRecogize->m_ContinueVoiceTraining = false;

            if (gVowEngine.getArg != NULL) {
                gVowEngine.getArg(vowe_argid_trainLastUtteranceSnr,
                        arg_value_get_cast(&snr_value),
                        0);
            }
            ALOGD("snr: %f", snr_value);
            pVoiceRecogize->notify_data[0] = (char)snr_value;
            pVoiceRecogize->notify_data[1] = 0;
            if (pVoiceRecogize->notify_data[0] <= 0) {
                pVoiceRecogize->notify_data[0] = 1;  //UTF will let "0" be end condition
            } else if (pVoiceRecogize->notify_data[0] > 100) {
                pVoiceRecogize->notify_data[0] = 100;
            }
            pRtnContactNameArray[0] = &pVoiceRecogize->notify_data[0];
            switch (msg) {
                case vowe_no_speech:
                    notify_back = 6;
                    break;
                case vowe_ready_to_enroll:
                    pVoiceRecogize->getUtterancePcm();
                    notify_back = 0;
                    pVoiceRecogize->m_bNeedToWait = true;
                    pVoiceRecogize->m_bNeedToRelease = false;
                    break;
                case vowe_good_utterance:
                    pVoiceRecogize->getUtterancePcm();
                    notify_back = 1;
                    break;
                case vowe_bad_utterance:
                    notify_back = 4;//5;
                    break;
                case vowe_noisy_utterance:
                    notify_back = 2;
                    break;
                case vowe_low_snr_utterance:
                    notify_back = 3;
                    break;
                case vowe_mismatched_cmd_utterance:
                    notify_back = 4;
                    break;
                default:
                    ALOGD("[error] return value error, need check lib");
                    break;
            }
            ALOGD("PCMDiagonosis after, msg = %d, confidence = %d, snr = %d",
                  msg,
                  confidence,
                  pVoiceRecogize->notify_data[0]);

            if (pVoiceRecogize->m_onStartRecording == true) {
                pVoiceRecogize->notify(VOICE_TRAINING_PROCESS, VOICE_ON_STOP_RECORD, 0);
                pVoiceRecogize->m_onStartRecording = false;
            }
            if (pVoiceRecogize->m_onStartProcessing == true) {
                pVoiceRecogize->notify(VOICE_TRAINING_PROCESS, VOICE_ON_STOP_PROCESS, 0);
                pVoiceRecogize->m_onStartProcessing = false;
            }
            pVoiceRecogize->notify(VOICE_TRAINING, notify_back, confidence, pRtnContactNameArray);

            if ((msg == vowe_ready_to_enroll) && (pVoiceRecogize->m_bNeedToWait)) {
                pVoiceRecogize->recordLockWait(kWaitingTimeOutMS);
            }
            // msg==0 -   voice is enough, it is going to training
            // msg==1 -   voice is not enough, recording on going
            // msg==2 -   the environment is too noisy
            // msg==3 -   the sound is too little
            // msg==4 -   the password is not match with previous password
            // msg==5 -   the password is already exist
            // msg==11 -  the password is not match with the password specified by vendor
        }
    }
    if (pULBuf1_temp != NULL) delete [] pULBuf1_temp;
    if (pULBuf2_temp != NULL) delete [] pULBuf2_temp;
    pULBuf1_temp = NULL;
    pULBuf2_temp = NULL;
    pULBuf1 = NULL;
    pULBuf2 = NULL;

    pVoiceRecogize->setTrainingThreadStarted(false);

    ALOGD("Training voice thread out -");
    pthread_exit(NULL);
    return 0;
}

/*
void writeCallBackWrapper(void *me, const short *pBuf, int64_t length)
{
    //VoiceCmdRecognition *pVoiceRecognize = (VoiceCmdRecognition *)me;
    //pVoiceRecognize->writeWavFile(pBuf, length);
}
*/

bool VoiceCmdRecognition::isFeatureOptionEnabled(char *option) {
    bool ret = false;

    /* Get AudioParamOptions.xml Project config */
    AppOps *appOps = appOpsGetInstance();

    if (appOps == NULL) {
        ALOGE("%s(), Error: AppOps == NULL", __FUNCTION__);
    } else {
        AppHandle *appHandle = appOps->appHandleGetInstance();
        const char *strFo = appOps->appHandleGetFeatureOptionValue(appHandle, option);
        if (strFo != NULL) {
            if (strcmp(strFo, "yes") == 0) {
                ret = true;
            }
        }
        ALOGD("%s(), option = %s, ret = %d", __FUNCTION__, option, ret);
    }
    return ret;
}

void VoiceCmdRecognition::getFeatureOption() {
    ALOGD("%s()", __FUNCTION__);

    m_VowFeatureOption.isDualMicSupport = isFeatureOptionEnabled("MTK_DUAL_MIC_SUPPORT");
    m_VowFeatureOption.isNormalRecordEnroll = isFeatureOptionEnabled("MTK_VOW_NORMAL_RECORD_ENROLL");
}

VoiceCmdRecognition::VoiceCmdRecognition(audio_source_t inputSource, unsigned int sampleRate, unsigned int channelCount) :
    m_RecognitionMode(VOICE_IDLE_MODE),
    m_bStarted(false),
    m_bNeedToWait(false),
    m_bNeedToRelease(true),
    m_enrolling(false),
    m_onStartRecording(false),
    m_onStartProcessing(false),
    m_setTrainingThreshold(false),
    m_setTrainingTimeout(false),
    m_bStartRecordBackroundVoice(false),
    m_already_read(false),
    m_Training_Lib_Init(false),
    m_CaptureVoicePause(false),
    m_ContinueVoiceTraining(false),
    m_bIsTrainingThreadStarted(false),
    m_PatternFd(-1),
    m_bIsCaptureThreadStarted(false),
    m_BackroundVoiceCount(0),
    m_trainingTimes(0),
    m_trainingThreshold(50),
    m_trainingTimeoutMsec(5000),
    m_voiceULBuf1(NULL),
    m_voiceULBuf2(NULL),
    m_ReadDataTid(0),
    //m_bSpecificRefMic(false),
    m_pListener(0),
    m_SampleRate(sampleRate),
    m_Channels(channelCount),
    m_PasswordFd(-1),
    m_FeatureFd(-1),
    m_CommandId(-1),
    m_VoiceMode(VOICE_NORMAL_MODE),
    m_WakeupMode(vowe_mode_pdk_fullRecognizer),
    m_pStrWakeupInfoPath(NULL),
    m_UtterancePcmSize(0),
    m_UtterancePcm(NULL)
{
    ALOGD("VoiceCmdRecognition construct in +");
    ALOGD("input source:%d,sampe rate:%d,Channel count:%d, m_InputSource%d, inputSource%d", m_InputSource,m_SampleRate,m_Channels,m_InputSource,inputSource);
    memset(m_strPatternPath, 0, FILE_NAME_LEN_MAX);
    memset(m_strUBMPath, 0, FILE_NAME_LEN_MAX);
    memset(m_strUpgradeUBMPath, 0, FILE_NAME_LEN_MAX);
    memset(&m_rb_info1, 0, sizeof(struct ring_buffer_information));
    memset(&m_rb_info2, 0, sizeof(struct ring_buffer_information));
    if (pthread_mutex_init(&m_trainingThreadStartedMutex, NULL) != 0) {
        ALOGD("Failed to initialize m_trainingThreadStartedMutex!");
    }
    if (pthread_mutex_init(&m_captureThreadStartedMutex, NULL) != 0) {
        ALOGD("Failed to initialize m_captureThreadStartedMutex!");
    }
    if (pthread_mutex_init(&m_RecordMutex, NULL) != 0) {
        ALOGW("Failed to initialize m_RecordMutex!");
    }
    if (pthread_mutex_init(&m_BufMutex, NULL) != 0) {
        ALOGD("Failed to initialize m_BufMutex!");
    }
    if (pthread_cond_init(&m_RecordExitCond, NULL) != 0) {
        ALOGW("Failed to initialize m_RecordExitCond!");
    }
    memset(&m_VowFeatureOption, 0, sizeof(struct VOW_FEATURE_OPTION));
    getFeatureOption();

    if (!m_VowFeatureOption.isNormalRecordEnroll) {
        m_InputSource = AUDIO_SOURCE_HOTWORD;
    } else {
        m_InputSource = AUDIO_SOURCE_UNPROCESSED;
    }

    openVowEngine();
    if (gVowEngine.version != NULL) {
        char *voice_version;
        voice_version = (char *)gVowEngine.version();
        ALOGD("voice unlock SWIP version is:%s", voice_version);
    }
}

VoiceCmdRecognition::~VoiceCmdRecognition()
{
    ALOGD("%s, deconstruct in +", __FUNCTION__);
    if (m_pAudioStream != 0) {
        m_pAudioStream.clear();
    }

    if (m_pListener != 0) {
        m_pListener.clear();
    }

    if (m_PasswordFd >= 0) {
        ::close(m_PasswordFd);
    }
    if (m_PatternFd >= 0) {
        ::close(m_PatternFd);
    }
    if (m_FeatureFd >= 0) {
        ::close(m_FeatureFd);
    }

    if (m_voiceULBuf1 != NULL) {
        ALOGD("%s, m_voiceULBuf1 delete", __FUNCTION__);
        delete[] m_voiceULBuf1;
        m_voiceULBuf1 = NULL;
    }
    if (m_voiceULBuf2 != NULL) {
        ALOGD("%s, m_voiceULBuf2 delete", __FUNCTION__);
        delete[] m_voiceULBuf2;
        m_voiceULBuf2 = NULL;
    }

    closeVowEngine();
}

status_t VoiceCmdRecognition::initCheck()
{
    int ret = NO_INIT;
    if (m_pAudioStream != 0) {
        ret = NO_ERROR;
    }
    return ret;
}

status_t VoiceCmdRecognition::setVoicePasswordFile(int fd, int64_t offset, int64_t length)
{
    ALOGV("%s in +, fd = %d", __FUNCTION__, fd);
    if (fd < 0) {
        ALOGE("Invalid file descriptor: %d", fd);
        return -EBADF;
    }

    if (m_PasswordFd >= 0){
        ::close(m_PasswordFd);
    }

    m_PasswordFd = dup(fd);
    ALOGD("setVoicePasswordFile(): m_PasswordFd = %d, fd = %d, offse = %lld, length = %lld", m_PasswordFd, fd, (long long)offset, (long long)length);
    return OK;
}

status_t VoiceCmdRecognition::setVoicePatternFile(int fd, int64_t offset, int64_t length)
{
    ALOGD("%s in +, fd = %d", __FUNCTION__, fd);
    if (fd < 0) {
        ALOGE("Invalid file descriptor: %d", fd);
        return -EBADF;
    }

    if (m_PatternFd >= 0) {
        ::close(m_PatternFd);
    }

    m_PatternFd = dup(fd);
    ALOGD("setVoicePatternFile(): m_PatternFd = %d, fd = %d, offset: = %lld, length = %lld", m_PatternFd, fd, (long long)offset, (long long)length);
    return OK;
}

status_t VoiceCmdRecognition::setVoicePatternFile(const char *path)
{
    ALOGD("%s in +, path = %s", __FUNCTION__, path);
    if (path == NULL) {
        ALOGE("voice patter file path is null!!");
        return BAD_VALUE;
    }

    strncpy(m_strPatternPath, path, FILE_NAME_LEN_MAX - 1);
    return OK;
}

status_t VoiceCmdRecognition::setVoiceUBMFile(const char *path)
{
    ALOGD("%s in +, path = %s", __FUNCTION__, path);
    if (path == NULL) {
        ALOGE("UBM files path is null: %s", path);
        return BAD_VALUE;
    }
    String8 libPostfix = getEnginePostfix();
    if (libPostfix.length() > 0){
        int ret = snprintf(m_strUBMPath, sizeof(m_strUBMPath), "%s%s/",
                path, libPostfix.string());
        if (access(m_strUBMPath, R_OK) != 0) {
            ALOGE("%s(), m_strUBMPath = %s is incorrect! use the path from argument", __FUNCTION__, m_strUBMPath);
            memset(m_strUBMPath, 0, sizeof(m_strUBMPath));
            strncpy(m_strUBMPath, path, FILE_NAME_LEN_MAX - 1);
        }
    } else if (libPostfix.length() == 0) {
        strncpy(m_strUBMPath, path, FILE_NAME_LEN_MAX - 1);
    }
    ALOGD("%s(): m_strUBMPath = %s", __FUNCTION__, m_strUBMPath);

    return OK;
}

status_t VoiceCmdRecognition::setUpgradeVoiceUBMFile(const char *path)
{
    ALOGD("%s in +, path = %s", __FUNCTION__, path);
    if (path == NULL) {
        ALOGE("Upgrade UBM files path is null: %s", path);
        memset(m_strUpgradeUBMPath, 0, FILE_NAME_LEN_MAX);
        return OK;
    }

    strncpy(m_strUpgradeUBMPath, path, FILE_NAME_LEN_MAX - 1);

    return OK;
}

status_t VoiceCmdRecognition::setVoiceFeatureFile(int fd, int64_t offset, int64_t length)
{
    ALOGV("%s in +, fd = %d", __FUNCTION__, fd);
    if(fd<0) {
        ALOGE("Invalid feature file descriptor: %d", fd);
        return -EBADF;
    }

    if (m_FeatureFd >= 0){
        ::close(m_FeatureFd);
    }

    m_FeatureFd = dup(fd);
    ALOGD("setVoiceFeatureFile(): m_FeatureFd: = %d, fd = %d, length = %lld ,offset = %lld", m_FeatureFd, fd, (long long)length, (long long)offset);
    return OK;
}

status_t VoiceCmdRecognition::setCommandId(int id)
{
    ALOGV("%s in +, id = %d", __FUNCTION__, id);
    if (id<0) {
        ALOGE("command id is invalide: %d", id);
        return BAD_VALUE;
    }
    m_CommandId = id;
    return OK;
}

status_t VoiceCmdRecognition::setInputMode(int input_mode)
{
    ALOGD("%s +, input_mode = %d", __FUNCTION__, input_mode);

    if (input_mode >= VOICE_MODE_NUM_MAX) {
        ALOGW("input mode is invalide!!");
        return BAD_VALUE;
    }

    m_VoiceMode = input_mode;
    return OK;
}

/*for voice wakeup feature*/
status_t VoiceCmdRecognition::setVoiceTrainingMode(int mode)
{
    ALOGD("%s +, recongnition mode = %d", __FUNCTION__, mode);
    // TODO: always set mode as vowe_mode_pdk_fullRecognizer currently
#ifdef SET_WAKEUP_MODE_ENABLED
    if (mode < 0 || mode > VOICE_WAKE_UP_MODE_NUM) {
        ALOGD("setVoiceTrainingMode mode error!!");
        return BAD_VALUE;
    }

    if (mode == VOICE_WAKEUP_NO_RECOGNIZE) {
        m_WakeupMode = vowe_mode_pdk_fullRecognizer;
    } else if (mode == VOICE_WAKEUP_RECOGNIZE) {
        m_WakeupMode = vowe_mode_udk_lowPower;
    }
#else
    m_WakeupMode = vowe_mode_pdk_fullRecognizer;
#endif
    ALOGD("m_WakeupMode = %d", m_WakeupMode);
    return OK;
}

status_t VoiceCmdRecognition::setVoiceWakeupInfoPath(const char * path)
{
    int size = 0;
    if (path == NULL) {
        ALOGD("%s, file path is NULL!", __FUNCTION__);
        return BAD_VALUE;
    }

    ALOGV("%s +, file path: %s", __FUNCTION__, path);
    size = strlen(path);
    if (size > FILE_NAME_LEN_MAX) {
        ALOGD("%s, file path is too long length:%d!", __FUNCTION__, size);
        return BAD_VALUE;
    }

    if (m_pStrWakeupInfoPath == NULL) {
        m_pStrWakeupInfoPath = new char[size + 1];
        memset(m_pStrWakeupInfoPath, 0, (size + 1) * sizeof(char));
    }

    if (m_pStrWakeupInfoPath) {
        strncpy(m_pStrWakeupInfoPath, path, size);
    } else {
        ALOGW("setVoiceWakeupInfoPath allocate memory fail!");
        return BAD_VALUE;
    }

    return OK;
}

status_t VoiceCmdRecognition::setVoiceWakeupMode(int mode)
{
    ALOGD("%s +, mode = %d", __FUNCTION__, mode);
    // TODO: always set mode as vowe_mode_pdk_fullRecognizer currently
#ifdef SET_WAKEUP_MODE_ENABLED
    if (mode < 0 || mode > VOICE_WAKE_UP_MODE_NUM) {
        ALOGD("setVoiceWakeupMode mode error!!");
        return BAD_VALUE;
    }

    m_WakeupMode = mode;
#else
    m_WakeupMode = vowe_mode_pdk_fullRecognizer;
#endif
    return OK;
}

status_t VoiceCmdRecognition::pauseVoiceTraining()
{
    ALOGD("%s +", __FUNCTION__);
    if (m_CaptureVoicePause == false) {
        m_CaptureVoicePause = true;
    }
    return OK;
}

status_t VoiceCmdRecognition::getTrainigTimes(int *times)
{
    ALOGD("%s +", __FUNCTION__);
    int err;

    if (times == NULL) {
        ALOGE("%s(), Null pointer argument", __FUNCTION__);
        return BAD_VALUE;
    }

    if (gVowEngine.getArg == NULL) {
        ALOGE("%s(), load getArg fail", __FUNCTION__);
        return BAD_VALUE;
    }
    err = gVowEngine.getArg(vowe_argid_trainUtteranceNumber,
            arg_value_get_cast(times),
            0);
    if (err != vowe_ok) {
        ALOGE("%s(), error!! = %d", __FUNCTION__, err);
        return BAD_VALUE;
    } else {
        ALOGD("%s(), times = %d", __FUNCTION__, *times);
        if (*times == 0) {
            ALOGD("%s(), SWIP return invalid time, force return 5", __FUNCTION__);
            *times = 5;
        }
        m_trainingTimes = *times;
        return OK;
    }
}

status_t VoiceCmdRecognition::setUtteranceTrainingTimeout(int msec)
{
    ALOGD("%s +, msec = %d", __FUNCTION__, msec);

    if ( msec < 3000 || msec > 6000 ) {
        ALOGE("%s, bad value", __FUNCTION__);
        return BAD_VALUE;
    }

    m_trainingTimeoutMsec = msec;
    m_setTrainingTimeout = true;
    return OK;
}

status_t VoiceCmdRecognition::setTrainingThreshold(int threshold)
{
    ALOGD("%s +, threshold = %d", __FUNCTION__, threshold);

    if ( threshold < 0 || threshold > 100 ) {
        ALOGE("%s, bad value", __FUNCTION__);
        return BAD_VALUE;
    }
    m_trainingThreshold = threshold;
    m_setTrainingThreshold = true;
    return OK;
}

status_t VoiceCmdRecognition::getTrainingThreshold(int *threshold)
{
    ALOGD("%s +", __FUNCTION__);

    if (threshold == NULL) {
        ALOGE("Null pointer argument");
        return BAD_VALUE;
    }

    *threshold = m_trainingThreshold;
    ALOGD("%s(): threshold = %d", __FUNCTION__, *threshold);
    return OK;
}

status_t VoiceCmdRecognition::continueVoiceTraining()
{
    ALOGD("%s() +", __FUNCTION__);

    ALOGD("%s(), push to talk", __FUNCTION__);
    if (gVowEngine.pushToTalk != NULL) {
        if (gVowEngine.pushToTalk() == vowe_bad) {
            ALOGE("%s(), VOWE_Trainer_pushToTalk error!!", __FUNCTION__);
        }
    }
    m_ContinueVoiceTraining = true;
    if (m_onStartRecording == false) {
        notify(VOICE_TRAINING_PROCESS, VOICE_ON_START_RECORD, 0);
        m_onStartRecording = true;
    }
    if (m_onStartProcessing == false) {
        notify(VOICE_TRAINING_PROCESS, VOICE_ON_START_PROCESS, 0);
        m_onStartProcessing = true;
    }
    if (m_CaptureVoicePause == true) {
        ALOGD("%s, resume Capture Voice", __FUNCTION__);
        m_CaptureVoicePause = false;
    }

    releaseUtterancePcm();
    return OK;
}

status_t VoiceCmdRecognition::startCaptureVoice(unsigned int mode)
{
    ALOGD("%s +", __FUNCTION__);

    // for create thread timeout
    struct timeval now;
    struct timespec timeout;
    gettimeofday(&now, NULL);
    timeout.tv_sec  = now.tv_sec + 3;
    timeout.tv_nsec = now.tv_usec*1000;

    // parameters mode:
    // VOICE_IDLE_MODE for idle mode, created but not work
    // VOICE_PW_TRAINING_MODE for voice password training.
    if ((popcount(mode)!=1) || ((mode&VOICE_RECOGNIZE_MODE_ALL)==0))
    return BAD_VALUE;

    if (m_RecognitionMode & VOICE_PW_TRAINING_MODE) {
        ALOGE("voice password training is running");
        return BAD_VALUE;
    }

    // for voice recognition initialize
    status_t ret = OK;
    ret = voiceRecognitionInit(mode);
    if (ret != OK) {
        ALOGW("startCaptureVoice, error!!, voice recognition fail!");
        return ret;
    }

    if (!m_VowFeatureOption.isNormalRecordEnroll) {
        // do not call AudioSystem methods with mLock held
        AudioSystem::setParameters(0, String8("vow_hotword_record_path=on"));
        AudioSystem::setParameters(0, String8("MTK_VOW_TRAINING=1"));
        ret = AudioSystem::acquireSoundTriggerSession(&m_Session, &m_IoHandle, &m_Device);
        ALOGD("%s(), m_Session = %d, m_Session = %d, m_Device = %d", __FUNCTION__, (int)m_Session, (int)m_IoHandle, (int)m_Device);
        if (ret != NO_ERROR) {
            ALOGE("%s(), acquire sound trigger session error!!, ret = %d", __FUNCTION__, ret);
            return ret;
        }
    } else {
        // use vow enroll scene gain
        AudioSystem::setParameters(0, String8("SetAudioCustomScene=VOW_ENROLL"));
    }

    if (m_voiceULBuf1 != NULL) {
        ALOGD("%s, 1. m_voiceULBuf1 need to delete", __FUNCTION__);
        delete[] m_voiceULBuf1;
        m_voiceULBuf1 = NULL;
    }
    if (m_voiceULBuf2 != NULL) {
        ALOGD("%s, 1. m_voiceULBuf2 need to delete", __FUNCTION__);
        delete[] m_voiceULBuf2;
        m_voiceULBuf2 = NULL;
    }
    ALOGD("m_voiceULBuf1 malloc new");
    m_voiceULBuf1 = new short[MAX_SAMPLE_LENGTH];
    if (m_voiceULBuf1 == NULL) {
        ALOGD("error!!, m_voiceULBuf1 malloc fail");
        goto exit;
    }
    ALOGD("m_voiceULBuf2 malloc new");
    m_voiceULBuf2 = new short[MAX_SAMPLE_LENGTH];
    if (m_voiceULBuf2 == NULL) {
        ALOGD("error!!, m_voiceULBuf2 malloc fail");
        goto exit;
    }
    pthread_mutex_lock(&m_BufMutex);
    pthread_mutex_unlock(&m_BufMutex);
    m_already_read = false;

    ret = startAudioStream();
    if (ret != OK) {
        ALOGE("%s(), startAudioStream fail! call Release, mode = %d", __FUNCTION__, mode);
        voiceRecognitionRelease(mode);
        goto exit;
    }

    m_RecognitionMode = m_RecognitionMode | mode;
    m_onStartRecording = false;
    m_onStartProcessing = false;
    if (m_onStartRecording == false) {
        notify(VOICE_TRAINING_PROCESS, VOICE_ON_START_RECORD, 0);
        m_onStartRecording = true;
    }
    m_bStartRecordBackroundVoice = true;
    m_BackroundVoiceCount = 0;
    m_CaptureVoicePause = false;
    m_ContinueVoiceTraining = true;
/*
    if (m_onStartProcessing == false) {
        notify(VOICE_TRAINING_PROCESS, VOICE_ON_START_PROCESS, 0);
        m_onStartProcessing = true;
    }
*/
    ALOGD("%s() -", __FUNCTION__);
    return OK;
exit:
    ALOGD("%s(), error handle", __FUNCTION__);
    if (m_voiceULBuf1 != NULL) {
        ALOGD("%s(), error!!, m_voiceULBuf1 need to delete", __FUNCTION__);
        delete[] m_voiceULBuf1;
        m_voiceULBuf1 = NULL;
    }
    if (m_voiceULBuf2 != NULL) {
        ALOGD("%s(), error!!, m_voiceULBuf2 need to delete", __FUNCTION__);
        delete[] m_voiceULBuf2;
        m_voiceULBuf2 = NULL;
    }
    if (!m_VowFeatureOption.isNormalRecordEnroll) {
        if (ret != NO_ERROR) {
            // do not call AudioSystem methods with mLock held
            AudioSystem::releaseSoundTriggerSession(m_Session);
            AudioSystem::setParameters(0, String8("MTK_VOW_TRAINING=0"));
            AudioSystem::setParameters(0, String8("vow_hotword_record_path=off"));
        }
    } else {
        AudioSystem::setParameters(0, String8("SetAudioCustomScene=Default"));
    }
    return ret;
}

bool VoiceCmdRecognition::getTrainingThreadStarted()
{
    bool ret = false;
    pthread_mutex_lock(&m_trainingThreadStartedMutex);
    ret = m_bIsTrainingThreadStarted;
    pthread_mutex_unlock(&m_trainingThreadStartedMutex);
    return ret;
}

bool VoiceCmdRecognition::getCaptureThreadStarted()
{
    bool ret = false;
    pthread_mutex_lock(&m_captureThreadStartedMutex);
    ret = m_bIsCaptureThreadStarted;
    pthread_mutex_unlock(&m_captureThreadStartedMutex);
    return ret;
}

bool VoiceCmdRecognition::setTrainingThreadStarted(bool started)
{
    pthread_mutex_lock(&m_trainingThreadStartedMutex);
    m_bIsTrainingThreadStarted = started;
    ALOGD("%s(), m_bIsTrainingThreadStarted = %d", __FUNCTION__, m_bIsTrainingThreadStarted);
    pthread_mutex_unlock(&m_trainingThreadStartedMutex);
    return true;
}

bool VoiceCmdRecognition::setCaptureThreadStarted(bool started)
{
    pthread_mutex_lock(&m_captureThreadStartedMutex);
    m_bIsCaptureThreadStarted = started;
    ALOGD("%s(), m_bIsCaptureThreadStarted = %d", __FUNCTION__, m_bIsCaptureThreadStarted);
    pthread_mutex_unlock(&m_captureThreadStartedMutex);
    return true;
}

status_t VoiceCmdRecognition::stopCaptureVoice(unsigned int mode)
{
    int count = 1000000;
    ALOGD("%s() +", __FUNCTION__);

    // parameters mode:
    // VOICE_IDLE_MODE for idle mode, created but not work
    // VOICE_PW_TRAINING_MODE for voice password training.
    if ((popcount(mode) != 1) || !(mode & VOICE_RECOGNIZE_MODE_ALL) || !(mode & m_RecognitionMode)) {
        ALOGW("%s(), mode = 0x%x, recognizing mode = 0x%x", __FUNCTION__, mode, m_RecognitionMode);
        ALOGD("%s(), re-entry, need to release", __FUNCTION__);
        voiceRecognitionRelease(mode);
        return OK;
    }

    while ((m_enrolling == true) && (count > 0)) {
        usleep(10000);
        count--;
    }

    m_RecognitionMode = m_RecognitionMode&(~mode);
    // signal TrainingVoiceLoop thread to go on.
    m_bNeedToWait = false;
    ALOGV("recordLockSignal()");
    recordLockSignal();
    ALOGV("stopCaptureVoice after signal--");

    ALOGV("%s(), mode = 0x%x, m_RecognitionMode = 0x%x", __FUNCTION__, mode, m_RecognitionMode);
    if (popcount(m_RecognitionMode) == 0) {
        m_bStarted = false;

        // stop the record stream to make sure record thread quit the loop. 
        bool isTrainingThreadStarted = getTrainingThreadStarted();
        bool isCaptureThreadStarted = getCaptureThreadStarted();
        while ((isTrainingThreadStarted == true) || (isCaptureThreadStarted == true)) {
            ALOGV("%s(), Wait: isTrainingThreadStarted = %d, isCaptureThreadStarted = %d", __FUNCTION__, isTrainingThreadStarted, isCaptureThreadStarted);
            usleep(2000);
            isTrainingThreadStarted = getTrainingThreadStarted();
            isCaptureThreadStarted = getCaptureThreadStarted();
        }
        ALOGD("%s(), Threads stopped: isTrainingThreadStarted = %d, isCaptureThreadStarted = %d", __FUNCTION__, isTrainingThreadStarted, isCaptureThreadStarted);
        if (m_pAudioStream != 0) {
            ALOGD("%s(), Stop and free AudioStream", __FUNCTION__);
            m_pAudioStream->stop();
            m_pAudioStream.clear();
            m_pAudioStream = NULL;
        }

        ALOGD("m_Tid wait thread exit");
        pthread_join(m_Tid, NULL);
        ALOGD("m_Tid wait thread exit done");
        ALOGD("m_ReadDataTid wait thread exit");
        pthread_join(m_ReadDataTid, NULL);
        ALOGD("m_ReadDataTid wait thread exit done");

        if (m_onStartRecording == true) {
            notify(VOICE_TRAINING_PROCESS, VOICE_ON_STOP_RECORD, 0);
            m_onStartRecording = false;
        }
        if (m_onStartProcessing == true) {
            notify(VOICE_TRAINING_PROCESS, VOICE_ON_STOP_PROCESS, 0);
            m_onStartProcessing = false;
        }
    }
    m_onStartRecording = false;
    m_onStartProcessing = false;
    m_ContinueVoiceTraining = false;

    if (m_voiceULBuf1 != NULL) {
        ALOGD("%s(), m_voiceULBuf1 delete", __FUNCTION__);
        delete[] m_voiceULBuf1;
        m_voiceULBuf1 = NULL;
    }
    if (m_voiceULBuf2 != NULL) {
        ALOGD("%s(), m_voiceULBuf2 delete", __FUNCTION__);
        delete[] m_voiceULBuf2;
        m_voiceULBuf2 = NULL;
    }
    if (!m_VowFeatureOption.isNormalRecordEnroll) {
        // do not call AudioSystem methods with mLock held
        AudioSystem::releaseSoundTriggerSession(m_Session);
        AudioSystem::setParameters(0, String8("MTK_VOW_TRAINING=0"));
        AudioSystem::setParameters(0, String8("vow_hotword_record_path=off"));
    } else {
        AudioSystem::setParameters(0, String8("SetAudioCustomScene=Default"));
    }
    if (mode == VOICE_PW_TRAINING_MODE) {
        if (m_bNeedToRelease) {
            ALOGD("%s(), call Release", __FUNCTION__);
            voiceRecognitionRelease(VOICE_PW_TRAINING_MODE);
        }
        m_bNeedToRelease = true;
    }

    releaseUtterancePcm();

    ALOGD("stopCaptureVoice -");
    return OK;
}

status_t VoiceCmdRecognition::startVoiceTraining()
{
    ALOGD("%s(), in +", __FUNCTION__);
    status_t ret = OK;

#if defined(MTK_VOW_ENABLE_CPU_BOOST)
    sp<IMtkPerf> power_service = NULL;
    int power_handle = 0;
    const int PERF_PARAMS_COUNT = 6;
    int perf_lock_opts[PERF_PARAMS_COUNT] = {
            PERF_RES_CPUFREQ_PERF_MODE, 1,  // force all cpu run at the highest freq
            PERF_RES_DRAM_OPP_MIN, 0,  // force DDR run at the highest freq
            PERF_RES_SCHED_BOOST, 1};  // big core first
    std::vector<int32_t> opt_list;
    power_service = IMtkPerf::tryGetService();
    if (power_service != NULL) {
        opt_list.assign(perf_lock_opts, (perf_lock_opts + PERF_PARAMS_COUNT));
        power_handle = power_service->perfLockAcquire(power_handle,
                CPU_BOOST_TIME_OUT,
                opt_list,
                PERF_PARAMS_COUNT);
        ALOGD("%s(), get powerService, power_service: %p, handle %d", __func__, power_service.get(), power_handle);
    } else {
        ALOGE("%s(), failed to get powerService", __func__);
    }
#endif

    pthread_create(&m_enrollTid, NULL, enrollTrainingThread, this);
    pthread_join(m_enrollTid, NULL);

#if defined(MTK_VOW_ENABLE_CPU_BOOST)
    if (power_service != NULL) {
       power_service->perfLockRelease(power_handle, 0);
    }
#endif

    ALOGD("%s(), in -", __FUNCTION__);
    return ret;
}

status_t VoiceCmdRecognition::setVoiceModelRetrain()
{
    ALOGD("%s(), in +", __FUNCTION__);
    status_t ret = OK;
    int confidence = 0;

#if defined(MTK_VOW_ENABLE_CPU_BOOST)
    sp<IMtkPerf> power_service = NULL;
    int power_handle = 0;
    const int PERF_PARAMS_COUNT = 6;
    int perf_lock_opts[PERF_PARAMS_COUNT] = {
            PERF_RES_CPUFREQ_PERF_MODE, 1,  // force all cpu run at the highest freq
            PERF_RES_DRAM_OPP_MIN, 0,  // force DDR run at the highest freq
            PERF_RES_SCHED_BOOST, 1};  // big core first
    std::vector<int32_t> opt_list;
    power_service = IMtkPerf::tryGetService();
    if (power_service != NULL) {
        opt_list.assign(perf_lock_opts, (perf_lock_opts + PERF_PARAMS_COUNT));
        power_handle = power_service->perfLockAcquire(power_handle,
                CPU_BOOST_TIME_OUT,
                opt_list,
                PERF_PARAMS_COUNT);
        ALOGD("%s(), get powerService, power_service: %p, handle %d", __func__, power_service.get(), power_handle);
    } else {
        ALOGE("%s(), failed to get powerService", __func__);
    }
#endif

    VOWE_Trainer_init_parameters trainerInitParameter;
    trainerInitParameter.mode = m_WakeupMode;
    trainerInitParameter.inChNum = 1;
    trainerInitParameter.modelFolder = m_strUBMPath;
    if (m_strUpgradeUBMPath[0] == 0) {
        trainerInitParameter.modelSubFolderModFile = NULL;
    } else {
        trainerInitParameter.modelSubFolderModFile = m_strUpgradeUBMPath;
    }
    trainerInitParameter.processRecordFolder = m_strPatternPath;
    trainerInitParameter.debugFolder = NULL;

    ALOGD("%s(), mode = %d", __FUNCTION__, trainerInitParameter.mode);
    ALOGD("%s(), modelFolder = %s", __FUNCTION__, trainerInitParameter.modelFolder);
    ALOGD("%s(), modelSubFolderModFile = %s", __FUNCTION__, trainerInitParameter.modelSubFolderModFile);
    ALOGD("%s(), processRecordFolder = %s", __FUNCTION__, trainerInitParameter.processRecordFolder);

    char filename_update_ul[] = "retrain.pcm";
    char trainPcmFile[100];

    int sprintf_ret = sprintf(trainPcmFile, "%s%s", m_strPatternPath, filename_update_ul);
    if (sprintf_ret < 0) {
        ALOGE("%s(), sprintf fail, sprintf_ret = %d", __FUNCTION__, sprintf_ret);
        return BAD_VALUE;
    }
    ALOGD("%s(), input path = %s", __FUNCTION__, trainPcmFile);

    // For R OTA to S @{
    if (!isFileExist(trainPcmFile)) {
        sprintf_ret = sprintf(trainPcmFile, "%s%s", m_strPatternPath, "training_ul.pcm");
        if (sprintf_ret < 0) {
            ALOGE("%s(), sprintf fail, sprintf_ret = %d", __FUNCTION__, sprintf_ret);
            return BAD_VALUE;
        }
        ALOGD("%s(), input path = %s", __FUNCTION__, trainPcmFile);
    }
    // @}

    if (gVowEngine.backgroundUpdate != NULL) {
        gVowEngine.backgroundUpdate(&trainerInitParameter, trainPcmFile, m_PatternFd, &confidence);
    } else {
        ALOGE("%s(), load backgroundUpdate fail", __func__);
    }

    voiceRecognitionRelease(VOICE_PW_RETRAIN_MODE);

    if (confidence == 100) {
        notify(VOICE_TRAINING_RETRAIN, VOICE_RETRAIN_SUCCESS, 0);
    } else {
        notify(VOICE_TRAINING_RETRAIN, VOICE_RETRAIN_FAIL, 0);
    }

#if defined(MTK_VOW_ENABLE_CPU_BOOST)
    if (power_service != NULL) {
       power_service->perfLockRelease(power_handle, 0);
    }
#endif

    ALOGD("%s(), mode = %d, confidence = %d", __FUNCTION__, trainerInitParameter.mode, confidence);
    return ret;
}

status_t VoiceCmdRecognition::getVoiceIntensity(int *maxAmplitude)
{
    ALOGV("%s(), in +", __FUNCTION__);

    if (maxAmplitude == NULL) {
        ALOGE("Null pointer argument");
        return BAD_VALUE;
    }

    if (m_pAudioStream != 0) {
        // get the intensity for recording PCM data
        *maxAmplitude = m_pAudioStream->getMaxAmplitude(0); //0: Channel L, 1: Channel_R
    } else {
        *maxAmplitude = 0;
    }
    ALOGV("%s(), maxAmplitude = %d",__FUNCTION__, *maxAmplitude);
    return OK;
}

status_t VoiceCmdRecognition::setListener(const sp<VoiceCmdRecognitionListener>& listener)
{
    ALOGV("%s(), in +", __FUNCTION__);
    m_pListener = listener;

    return NO_ERROR;
}

status_t VoiceCmdRecognition::getUtteranceSize(uint32_t *size)
{
    status_t ret = OK;
    if (size == NULL) {
        ALOGE("%s(), size == NULL!", __FUNCTION__);
        return ret;
    }
    *size = m_UtterancePcmSize;
    ALOGD("%s(), *size = %d", __FUNCTION__, *size);
    return ret;
}

status_t VoiceCmdRecognition::getUtterance(void *buffer, uint32_t size, uint32_t *writeSize)
{
    ALOGD("%s(), buffer = %p, size = %d, m_UtterancePcm = %p, m_UtterancePcmSize = %d",
            __FUNCTION__, buffer, size, m_UtterancePcm, m_UtterancePcmSize);

    status_t ret = OK;
    if (m_UtterancePcm == NULL) {
        ALOGE("%s(), m_UtterancePcm == NULL, invalid utterance", __FUNCTION__);
        *writeSize = 0;
        return ret;
    }
    if (m_UtterancePcmSize <= 0) {
        ALOGE("%s(), m_UtterancePcmSize <= 0, invalid utterance", __FUNCTION__);
        *writeSize = 0;
        return ret;
    }
    if (buffer == NULL) {
        ALOGE("%s(), buffer == NULL, invalid buffer", __FUNCTION__);
        *writeSize = 0;
        return ret;
    }

    uint32_t copyPcmSize = (size <= m_UtterancePcmSize)? size: m_UtterancePcmSize;
    memcpy(buffer, m_UtterancePcm, copyPcmSize);
    *writeSize = copyPcmSize;
    ALOGD("%s(), *writeSize = %d", __FUNCTION__, *writeSize);
#if VOW_UTTERANCE_PCM_DEBUG
    for (int i = 0; i < m_UtterancePcmSize; i++) {
        ALOGD("%s(), buffer[%d] = 0x%x", __FUNCTION__, i, ((uint8_t *)buffer)[i]);
    }
#endif
    return ret;
}
#if VOW_UTTERANCE_PCM_DEBUG
void dumpPcmData(const char *path, void *buffer, int count) {
    if (count == 0) {
        ALOGE("%s(), count == 0, invalid buffer", __FUNCTION__);
        return;
    }
    char filename[FILE_NAME_LEN_MAX];
    int sprintf_ret = sprintf(filename, "%sutterance_%d.pcm", path, GOOD_UTTERANCE_NUMBER);
    if (sprintf_ret < 0) {
        ALOGE("%s(), sprintf fail, sprintf_ret = %d", __FUNCTION__, sprintf_ret);
        return;
    }

    FILE *fp = fopen(filename, "wb+");
    if (fp != NULL) {
        int res = fwrite(buffer, 1, count, fp);
        if (res != count) {
            ALOGE("Failed to write dump file");
            return;
        }
        if (fclose(fp) != 0) {
            ALOGE("Failed to close dump file");
            return;
        }
    } else {
        ALOGE("open file fail");
        return;
    }
    if (GOOD_UTTERANCE_NUMBER < 5) {
        GOOD_UTTERANCE_NUMBER = GOOD_UTTERANCE_NUMBER + 1;
    } else {
        GOOD_UTTERANCE_NUMBER = 1;
    }
}
#endif
void VoiceCmdRecognition::getUtterancePcm()
{
    int ret = 0;
    int sampleNumber = 0;
    short *pcmBuffer = NULL;
    if (gVowEngine.getCurUtterance == NULL) {
        ALOGE("%s(), load getCurUtterance fail, return", __FUNCTION__);
        return;
    }
    ret = gVowEngine.getCurUtterance(&pcmBuffer, &sampleNumber);
    if (sampleNumber <= 0) {
        ALOGE("%s(), sampleNumber <= 0! return", __FUNCTION__);
        return;
    }
    if (pcmBuffer == NULL) {
        ALOGE("%s(), pcmBuffer == NULL! return", __FUNCTION__);
        return;
    }
    if (ret != vowe_ok) {
        ALOGE("%s(), VOWE_Trainer_getCurUtterance error! return", __FUNCTION__);
        return;
    }

    ALOGD("%s(), pcmBuffer = %p, sampleNumber = %d", __FUNCTION__, pcmBuffer, sampleNumber);
    // sample format 16bit to bytes
    m_UtterancePcmSize = sampleNumber * sizeof(short);
    m_UtterancePcm = new uint8_t[m_UtterancePcmSize];
    if (m_UtterancePcm == NULL) {
        ALOGE("%s(), allocate m_UtterancePcm failed! return", __FUNCTION__);
        m_UtterancePcmSize = 0;
        return;
    }
    memcpy(m_UtterancePcm, pcmBuffer, m_UtterancePcmSize);
    ALOGD("%s(), m_UtterancePcm = %p, m_UtterancePcmSize = %d", __FUNCTION__, m_UtterancePcm, m_UtterancePcmSize);
#if VOW_UTTERANCE_PCM_DEBUG
    for (int i = 0; i < m_UtterancePcmSize; i++) {
        ALOGD("%s(), m_UtterancePcm[%d] = 0x%x", __FUNCTION__, i, m_UtterancePcm[i]);
    }
    dumpPcmData(m_strPatternPath, m_UtterancePcm, m_UtterancePcmSize);
#endif
}

void VoiceCmdRecognition::releaseUtterancePcm()
{
    ALOGD("%s()", __FUNCTION__);
    m_UtterancePcmSize = 0;
    if (m_UtterancePcm != NULL) {
        delete[] m_UtterancePcm;
        m_UtterancePcm = NULL;
    }
}

bool VoiceCmdRecognition::saveRetrainPcm(void) {
    FILE *fpSource = NULL, *fpTarget = NULL;
    int nByteRead = 0;
    const uint32_t MAX_READ = 65536;
    char readBuffer[MAX_READ] = {0};
    bool ret = true;
    bool retSprintf = false;
    char fileSource[100] = "";
    char fileTarget[100] = "";

    retSprintf = sprintf(fileSource, "%s%s", m_strPatternPath, "training_ul.pcm");
    retSprintf = sprintf(fileTarget, "%s%s", m_strPatternPath, "retrain.pcm");

    if ((fpSource = fopen(fileSource, "rb")) != NULL) {
        if ((fpTarget = fopen(fileTarget, "wb")) != NULL) {
            while ((nByteRead = fread(readBuffer, sizeof(char), MAX_READ, fpSource)) > 0) {
                if (fwrite(readBuffer, sizeof(char), nByteRead, fpTarget) < nByteRead) {
                    ALOGE("%s(), fwrite retrain.pcm fail!", __func__);
                    ret = false;
                }
            }
        } else {
            ALOGE("%s(), fopen retrain.pcm fail!", __FUNCTION__);
            ret = false;
        }
    } else {
        ALOGE("%s(), fopen training_ul.pcm fail!", __FUNCTION__);
        ret = false;
    }

    if (fpSource) {
        if (fclose(fpSource)) {
            ALOGE("%s(), fclose training_ul.pcm fail!", __func__);
        }
    }

    if (fpTarget) {
        if (fclose(fpTarget)) {
            ALOGE("%s(), fclose retrain.pcm fail!", __func__);
        }
    }

    ALOGD("%s(), copy: %s, to %s", __FUNCTION__, fileSource, fileTarget);
    return ret;
}

void VoiceCmdRecognition::writeWavFile(const short *pBuf, int64_t length)
{
    short *buf_voice_cmd = NULL;
    ALOGV("%s in +", __FUNCTION__);
    if (pBuf==NULL||length==0) {
        ALOGW("buffer pointer is null or date length is zero~");
        return;
    }

    FILE *fd = fdopen(m_PasswordFd, "wb");
    if (fd==NULL) {
        ALOGE("open file descriptor fail, errorno: %s", strerror(errno));
        return;
    }

    // write wave header, this file is for unlock password.
    m_WavHeader.riff_id = ID_RIFF;
    m_WavHeader.riff_sz = length*sizeof(short) + 8 + 16 + 8;
    m_WavHeader.riff_fmt = ID_WAVE;
    m_WavHeader.fmt_id = ID_FMT;
    m_WavHeader.fmt_sz = 16;
    m_WavHeader.audio_format = FORMAT_PCM;
    m_WavHeader.num_channels = 1;
    m_WavHeader.sample_rate = m_SampleRate;
    m_WavHeader.byte_rate = m_WavHeader.sample_rate * m_WavHeader.num_channels * 2;
    m_WavHeader.block_align = m_WavHeader.num_channels * 2;
    m_WavHeader.bits_per_sample = 16;
    m_WavHeader.data_id = ID_DATA;
    m_WavHeader.data_sz = length*sizeof(short);

    // apply gain for voice command playing file
    buf_voice_cmd = new short[length];
    memcpy(buf_voice_cmd, pBuf, length * sizeof(short));
    for (int i = 0; i < length; i++) {
        buf_voice_cmd[i] = ClipToShort((int)buf_voice_cmd[i] * (int)PCM_FILE_GAIN);
    }

    size_t writeCount = 1;
    size_t writeCountRet = 0;
    int ret = 0;
    writeCountRet = fwrite(&m_WavHeader, sizeof(m_WavHeader), writeCount, fd);
    if (writeCountRet < writeCount) {
        ALOGE("%s(), write m_WavHeader fail! writeCountRet(%d) < writeCount(%d)",
                __FUNCTION__, (int)writeCountRet, (int)writeCount);
    }
    writeCountRet = fwrite((const void *)buf_voice_cmd, length * sizeof(short), writeCount, fd);
    if (writeCountRet < writeCount) {
        ALOGE("%s(), write buf_voice_cmd fail! writeCountRet(%d) < writeCount(%d)",
                __FUNCTION__, (int)writeCountRet, (int)writeCount);
    }
    if (buf_voice_cmd != NULL) {
        delete[] buf_voice_cmd;
    }
    ret = fflush(fd);
    if (ret < 0) {
        ALOGE("%s(), fflush fail! ret = %d", __FUNCTION__, ret);
    }
    ret = fclose(fd);
    if (ret < 0) {
        ALOGE("%s(), fclose fail! ret = %d", __FUNCTION__, ret);
    }
}

void VoiceCmdRecognition::notify(int message, int ext1, int ext2, char **ext3)
{
    ALOGD("notify in + msg %d, ext1 %d, ext2 %d", message, ext1, ext2);
    m_pListener->notify(message, ext1, ext2, ext3);
}

void VoiceCmdRecognition::recordLockSignal()
{
    // for sync recording, signal to record lock wait
    pthread_mutex_lock(&m_RecordMutex);
    pthread_cond_signal(&m_RecordExitCond);
    pthread_mutex_unlock(&m_RecordMutex);
}

int VoiceCmdRecognition::recordLockWait(int delayMS)
{
    int ret = 0;
    // wait record signal, if delayMs is not 0, it will time out when reachs the delayMS time.
    pthread_mutex_lock(&m_RecordMutex);
    if (delayMS!=0) {
        struct timeval now;
        struct timespec timeout;
        gettimeofday(&now, NULL);
        timeout.tv_sec  = now.tv_sec + delayMS / 1000;
        timeout.tv_nsec = now.tv_usec * 1000;
        ret = pthread_cond_timedwait(&m_RecordExitCond, &m_RecordMutex, &timeout);
    }else {
        ret = pthread_cond_wait(&m_RecordExitCond, &m_RecordMutex);
    }
    pthread_mutex_unlock(&m_RecordMutex);
    ALOGV("recordLockWait ret %d", ret);
    return ret;
}

status_t VoiceCmdRecognition::voiceRecognitionInit(unsigned int mode)
{
    ALOGD("voiceRecognitionInit in +");
    ALOGD("FRAMEWORK_VOW_RECOG_VER %s", FRAMEWORK_VOW_RECOG_VER);
    status_t ret = OK;

    switch(mode) {
        case VOICE_PW_TRAINING_MODE:
            if ((m_CommandId < 0) || (m_PatternFd < 0) || (m_FeatureFd < 0)) {
                ALOGE("parameters do not initialize, command id: %d, pattern fd: %d, feature fd: %d", m_CommandId, m_PatternFd, m_FeatureFd);
                return BAD_VALUE;
            }

            VOWE_Trainer_init_parameters trainerInitParameter;
            trainerInitParameter.mode = m_WakeupMode;
            trainerInitParameter.inChNum = 1;
            trainerInitParameter.modelFolder = m_strUBMPath;
            if (m_strUpgradeUBMPath[0] == 0) {
                trainerInitParameter.modelSubFolderModFile = NULL;
            } else {
                trainerInitParameter.modelSubFolderModFile = m_strUpgradeUBMPath;
            }
            trainerInitParameter.processRecordFolder = m_strPatternPath;
            trainerInitParameter.debugFolder = NULL;

            ALOGD("%s(), mode = %d", __FUNCTION__, trainerInitParameter.mode);
            ALOGD("%s(), modelFolder = %s", __FUNCTION__, trainerInitParameter.modelFolder);
            ALOGD("%s(), modelSubFolderModFile = %s", __FUNCTION__, trainerInitParameter.modelSubFolderModFile);
            ALOGD("%s(), processRecordFolder = %s", __FUNCTION__, trainerInitParameter.processRecordFolder);

            if (m_Training_Lib_Init == false) {
                if (gVowEngine.init != NULL) {
                    if (gVowEngine.init(&trainerInitParameter) == vowe_bad) {
                        ALOGE("error!! Traning init fail!");
                        ret = BAD_VALUE;
                        break;
                    } else {
                        m_Training_Lib_Init = true;
                    }
                } else {
                    ALOGE("%s(), load init fail!", __FUNCTION__);
                    ret = BAD_VALUE;
                    break;
                }
            } else {
                ALOGE("error!! m_Training_Lib_Init is not NULL, please check previous training flow!");
                ret = BAD_VALUE;
                break;
            }
            /* Set Training Timeout */
            if (m_setTrainingTimeout) {
                if (gVowEngine.setArg != NULL) {
                    if (gVowEngine.setArg(vowe_argid_trainTimeout,
                            arg_value_set_cast((int)m_trainingTimeoutMsec),
                            0) != vowe_ok) {
                        ALOGE("%s(), error!! ", __FUNCTION__);
                        ret = BAD_VALUE;
                        break;
                    } else {
                        ret = OK;
                    }
                } else {
                    ALOGE("%s(), load setArg fail!!", __FUNCTION__);
                    ret = BAD_VALUE;
                    break;
                }
            }
            /* Set Training Threshold */
            if (m_setTrainingThreshold) {
                if (gVowEngine.setArg != NULL) {
                    if (gVowEngine.setArg(vowe_argid_trainGlobalConfidenceThresholds,
                            arg_value_set_cast((float)m_trainingThreshold),
                            0) != vowe_ok) {
                        ALOGE("%s(), error!!", __FUNCTION__);
                        ret = BAD_VALUE;
                        break;
                    } else {
                        ret = OK;
                    }
                } else {
                    ALOGE("%s(), load setArg fail!!", __FUNCTION__);
                    ret = BAD_VALUE;
                    break;
                }
            }
            /* Set Warm Up Frame Count, 1frame = 10ms */
            if (gVowEngine.setArg != NULL) {
                if (gVowEngine.setArg(vowe_argid_warmUpFrameNum,
                        arg_value_set_cast(BACKGROUND_RECORD_SAMPLE_CNT),
                        0) != vowe_ok) {
                    ALOGE("%s(), error!!", __FUNCTION__);
                    ret = BAD_VALUE;
                    break;
                } else {
                    ret = OK;
                }
            } else {
                ALOGE("%s(), load setArg fail!!", __FUNCTION__);
                ret = BAD_VALUE;
                break;
            }
            break;
        default:
            ALOGE("voiceRecognitionInit - mode: %d is unkown", mode);
            ret = BAD_VALUE;
            break;
    }
    return ret;
}

status_t VoiceCmdRecognition::voiceRecognitionRelease(unsigned int mode)
{
    ALOGD("voiceRecognitionRelease in +");

    switch(mode) {
        case VOICE_PW_TRAINING_MODE:
            if (m_Training_Lib_Init == true) {
                if (gVowEngine.release != NULL) {
                    if (gVowEngine.release() == vowe_bad) {
                        ALOGE("Training Release init fail!");
                    } else {
                        m_Training_Lib_Init = false;
                    }
                } else {
                    ALOGE("%s(), load release fail!", __FUNCTION__);
                }
            }
            if (m_PasswordFd >= 0)
                ::close(m_PasswordFd);
            m_PasswordFd = -1;

            if (m_PatternFd >= 0)
                ::close(m_PatternFd);
            m_PatternFd = -1;

            if (m_FeatureFd >= 0)
                ::close(m_FeatureFd);
            m_FeatureFd = -1;
            break;
        case VOICE_PW_RETRAIN_MODE:
            if (m_PasswordFd >= 0)
                ::close(m_PasswordFd);
            m_PasswordFd = -1;

            if (m_PatternFd >= 0)
                ::close(m_PatternFd);
            m_PatternFd = -1;

            if (m_FeatureFd >= 0)
                ::close(m_FeatureFd);
            m_FeatureFd = -1;
            break;
        default:
            ALOGE("voiceRecognitionRelease - mode: %d is unkown", mode);
            break;
    }
    ALOGD("voiceRecognitionRelease in -");
    return OK;
}

status_t VoiceCmdRecognition::startAudioStream()
{
    ALOGD("startAudioStream in +");
    // for create thread timeout
    struct timeval now;
    struct timespec timeout;
    gettimeofday(&now, NULL);
    timeout.tv_sec  = now.tv_sec + 3;
    timeout.tv_nsec = now.tv_usec * 1000;

    if (!m_bStarted) {
        if (m_VowFeatureOption.isDualMicSupport) {
            m_Channels = m_VoiceMode == VOICE_HEADSET_MODE ? 1 : 2;
        } else {
            m_Channels = 1;
        }

        m_pAudioStream = new AudioStream(m_InputSource, m_SampleRate, m_Channels, m_Session, !m_VowFeatureOption.isNormalRecordEnroll);
        AudioSystem::getParameters(0, String8("GET_FSYNC_FLAG=0"));
        AudioSystem::getParameters(0, String8("GET_FSYNC_FLAG=1"));
        m_pAudioStream->enterBackupFilePath(m_strPatternPath);
        if (m_pAudioStream == 0 || m_pAudioStream->start() != OK) {
            ALOGE("start capture voice fail");
            return UNKNOWN_ERROR;
        }

        m_bStarted = true;
        pthread_mutex_lock(&m_RecordMutex);

        pthread_mutex_lock(&m_BufMutex);
        m_rb_info1.write_pointer = 0;
        m_rb_info1.read_pointer = 0;
        m_rb_info1.buffer_byte_count = MAX_SAMPLE_LENGTH * sizeof(short);
        m_rb_info1.buffer_base_pointer = (uint8_t *)&m_voiceULBuf1[0];

        m_rb_info2.write_pointer = 0;
        m_rb_info2.read_pointer = 0;
        m_rb_info2.buffer_byte_count = MAX_SAMPLE_LENGTH * sizeof(short);
        m_rb_info2.buffer_base_pointer = (uint8_t *)&m_voiceULBuf2[0];
        pthread_mutex_unlock(&m_BufMutex);

        pthread_create(&m_Tid, NULL, TrainingVoiceLoop, this);
        pthread_create(&m_ReadDataTid, NULL, captureVoiceLoop, this);
        if (pthread_cond_timedwait(&m_RecordExitCond, &m_RecordMutex, &timeout) == ETIME) {
            if (m_pAudioStream != 0) {
                m_pAudioStream->stop();
            }
            pthread_mutex_unlock(&m_RecordMutex);
            m_bStarted = false;
            return UNKNOWN_ERROR;
        }
        pthread_mutex_unlock(&m_RecordMutex);
    }else {
        ALOGD("startAudioStream already started!");
    }

    return OK;
}
