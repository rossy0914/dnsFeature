import argparse
import timeit
import os
import numpy as np
import pandas as pd
import xgboost as xgb
from scipy.stats import kurtosis
from sklearn.model_selection import GridSearchCV
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.decomposition import PCA, NMF
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC,NuSVC,LinearSVC
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.metrics import confusion_matrix, classification_report
from sklearn import metrics
import matplotlib.pyplot as plt

def getopt():
    parser = argparse.ArgumentParser(description='train convolutioned csv file with RF')
    parser.add_argument("train_csv")
    parser.add_argument("test_csv")
    

    args = parser.parse_args()
    return args

def sklearn_train(train,test):
    
    fw_cor = open('./correct_kurt.txt','a')
    fw_unk = open('./unknown_kurt.txt','a')
    fw_wrg = open('./wrong_kurt.txt','a')

    train_df = pd.DataFrame(pd.read_csv(train,low_memory=False))    
    test_df = pd.DataFrame(pd.read_csv(test,low_memory=False))
    del train_df['0']
    del train_df['nsNum']
    del train_df['trun flag Seq']
    del test_df['0']
    del test_df['nsNum']
    del test_df['trun flag Seq']
    #train_df = train_df[train_df['ip'] != '185.94.111.1']
    #test_df = test_df[test_df['ip'] != '185.94.111.1']

    '''
    #testing unknown label...
    train_df = train_df[train_df['ip'] != rem_ip]
    print("ip: ", rem_ip," is removed.")
    '''

    print("Label encoding...")
    ip_le = LabelEncoder()
    all_class = list()
    for col in train_df.columns.values:
        if train_df[col].dtypes == 'object':
            #print(col)
            le = LabelEncoder()
            data = train_df[col].append(test_df[col])
            le.fit(data.values)
            train_df[col] = le.transform(train_df[col])
            test_df[col] = le.transform(test_df[col])
            if col == 'ip':
                ip_le = le
                all_class = le.transform(np.unique(data))
     
    y_train = np.array(train_df['ip'])
    y_test = np.array(test_df['ip'])
    
    train_class = list(np.unique(y_train))
    test_class = list(np.unique(y_test))
    print(train_class)
    print("len:",len(train_class))
    print(test_class)
    print("len:",len(test_class))
    print("all class:",all_class)
    '''
    for i in all_class:
        print(i,": ",len(y_train[y_train == i]),'\t',len(y_test[y_test == i]))
    '''
    #featureset_name = ["all 31","no period and hour","top 10","top 20","from answer ips","original fields","statistical features","Seqeunce","non answer ips","TTL related","no seq"]
    #featureset_name = ["no period and hour","from answer ips","original fields","statistical features","Seqeunce","non answer ips","TTL related"]
    featureset_name = ["no seq"]
    featureset = [\
        #[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30],\
        [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28],\
        #[2,6,13,15,23,12,14,24,10,1],\
        #[2,6,13,15,23,12,14,24,10,1,20,16,9,19,5,25,22,28,11,8],\
        #[1,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24],\
        #[0,1,2,3,4,5,6,7,8,9],\
        #[10,11,12,13,14,15,16,17,18,19,20,21,22,23,24],\
        #[25,26,27,28],\
        #[0,2,3,4,5,6,7,8,9,25,26,27,28],\
        #[13,14,15,16,17,18,19,20,21,22],\
        #[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24]
    ]
    '''
    [0]"qryNum",[1]"ansNum",[2]"qryType",[3]"rcode",[4]"trunFlag",\
    [5]"respPktSize",[6]"domNameLen",[7]"respTime",\
    [8]"success",[9]"nxDomain",[10]"distASN",[11]"distCountry",[12]"distNet",\
    [13]"meanTTL",[14]"stdTTL",[15]"distTTL",[16]"totalTTL",[17]"TTL0",[18]"TTL1",[19]"TTL10",[20]"TTL100",[21]"TTL300",[22]"TTL900up",\
    [23]"distanceBtwIP",[24]"entTimezone",\
    [25]"qryType Seq",[26]"rcode Seq",[27]"success Seq",[28]"NXDomain Seq",
    [29]"period",[30]"hour",
    [31]"ip"
    '''
   
    clf_names = ["RF"]#"linearSVC","SVC","AdaBoost","knn,k=10","xgb","kmeans,n=15"]
    classifiers = [\
        #LinearSVC(class_weight='balanced'),\
        #NuSVC(decision_function_shape='ovo',nu=0.001,class_weight='balanced'),\
        #SVC(decision_function_shape='ovo',class_weight='balanced')
        RandomForestClassifier(n_estimators=100),\
        #AdaBoostClassifier(RandomForestClassifier(n_estimators=100),n_estimators=100, algorithm='SAMME'),\
        #KNeighborsClassifier(n_neighbors=10,leaf_size=10),\
        #xgb.XGBClassifier(n_estimators=100),\
        #KMeans(n_clusters=15)
        ]
    
    clf_params = [\
        { "max_features": [5,10,20,'auto'],"n_estimators":[10,50,100,200],"criterion":['gini','entropy']},\
        #{ "learning_rate":[2.0,1.0]},\
        #{"n_neighbors":[10,20],"leaf_size":[10,30]},\
        #{"learning_rate":[1.0,0.5]},\
        ]
   
    pred_m = dict()
    
    #for name, clf in zip(clf_names, classifiers):
    for name, featureset in zip(featureset_name, featureset):
        
        time1 = timeit.default_timer()
        #print("Feature Selection:",name)

        #pca = PCA(n_components=3)
        #selection = SelectKBest(k=20)
        #combined_features = FeatureUnion([("pca", pca), ("univ_select", selection)])
        #X_features = combined_features.fit(X_train, y_train).transform(X_train)
        #pipe = Pipeline([("features", combined_features), ("RF", clf)])
        
        X_train = np.array(train_df[featureset])
        X_test = np.array(test_df[featureset])
        
        clf = classifiers[0]
        #print("Fitting",name)
        #grid = GridSearchCV(clf, clf_params[0])
        clf.fit(X_train, y_train)
        #pipe = pipe.fit(X_train, y_train)
        print(name,"parameters: ",clf.get_params())
        #print(grid.best_params_)
        score = clf.score(X_test, y_test)
        #print(name,"Score: ", score)
        #score = pipe.score(X_test, y_test)
        #print(grid.grid_scores_)
        print(name, "mean accuracy: ", score)
        
        '''
        mean_scores = np.array(clf.cv_results_['mean_test_score'])
        # scores are in the order of param_grid iteration, which is alphabetical
        mean_scores = mean_scores.reshape(len(C_OPTIONS), -1, len(N_FEATURES_OPTIONS))
        # select score for best C
        mean_scores = mean_scores.max(axis=0)
        print(mean_scores)
        '''
        '''
        importances = clf.feature_importances_
        std = np.std([tree.feature_importances_ for tree in clf.estimators_], axis=0)
        indices = np.argsort(importances)[::-1]

        # Print the feature ranking
        print(name,"Feature ranking:")
        for f in range(X_train.shape[1]):
            print("%d. feature %d (%f)" % (f + 1, indices[f], importances[indices[f]]))
        
        '''
        if name == "kmeans":
            y_predict = clf.predict(X_train)
            homocomp = metrics.homogeneity_completeness_v_measure(y_train, y_predict)
            print("homo,complete,v_measure:", homocomp)
            print(metrics.calinski_harabaz_score(X_train, y_predict))

            
            continue
        
        y_predict = clf.predict(X_test)
        #y_test = ip_le.inverse_transform(y_test)
        #y_predict = ip_le.inverse_transform(y_predict)
        print(name,"classification report:")
        print(classification_report(y_test,y_predict))
        
        pred_m[name] =  confusion_matrix(y_test,y_predict)
        #print(name,"confusion matrix:")
        #print(pred_m[name])

        #print(name,"max:")
        #print(pred_m[name].argmax(axis=1))
        
        #print(name,"kurt calculation:")

        i = 0
        kurt_list = list()
        cor = list()
        wrg = list()
        weight_acc = 0
        for p in pred_m[name]:
            kurt = kurtosis(p)
            prob = p / sum(p)
            #print(prob)
            kurt_prob = kurtosis(prob)
            kurt_list.append((kurt_prob,p.argmax(),max(prob)))
            #print(i,": ",kurt_prob,", max:",p.argmax(),max(prob))
            print(i,": ",kurt_prob,", max:",p.argmax(),max(prob))
            
            i += 1
        
        j = 0
        k_norm = list()
        kurt_max = max(kurt_list,key=lambda item:item[0])[0]
        kurt_min = min(kurt_list,key=lambda item:item[0])[0]
        print("min:",kurt_min,", max:",kurt_max)
        for k in kurt_list:
            k_norm.append(k[0]/kurt_max)
            if k != -3:  
                if j == k[1]:
                    cor.append(k_norm[j])
                    fw_cor.write(str(k_norm[j])+'\t'+str(k[2])+'\n')
                    weight_acc += len(y_test[y_test == j])/len(y_test)
                else:
                    wrg.append(k_norm[j])
                    fw_wrg.write(str(k_norm[j])+'\t'+str(k[2])+'\n')
            if k_norm[j] > 0.8:
                print(j,k_norm[j],k[1],j==k[1],"confident")
                
            else:
                print(j,k_norm[j],k[1],j==k[1])
            j += 1
        
        time2 = timeit.default_timer()
        print("weighted accuracy = ",weight_acc)
        print("time cost: ",time2-time1)
        print("----------")
    
    fw_cor.close()
    fw_unk.close()
    fw_wrg.close()

def main():
    
    time1 = timeit.default_timer()
    
    args = getopt()
    dname = args.train_csv.rsplit('.csv')[0].split('/')[-1]
    
    sklearn_train(args.train_csv,args.test_csv)
    
    time2 = timeit.default_timer()
    
    print("Time cost: ", time2-time1)

if __name__ == "__main__":
    main()
