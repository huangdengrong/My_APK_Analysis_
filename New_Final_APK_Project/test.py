from androguard.misc import AnalyzeAPK
import networkx as nx
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.decompiler import decompiler
def test(apkfile):
    a = apk.APK(apkfile, False, 'r', None, 2)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.Analysis(d)
    dp = decompiler.DecompilerDAD(d, vmx)  # DAD是androguard内部的decompiler
    for k in d.get_classes():
        print(dp.get_source_class(k))
if __name__ == "__main__":
    path='D:\\APK_科研\\数据集\\APK_帅师姐\\jing-apk\\suamusica.suamusicaapp_1.13.2_[apkleecher.com].apk'
    test(path)